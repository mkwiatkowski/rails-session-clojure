(ns rails-session-clojure.base64
  (:import
    (java.util
      Base64
      Base64$Decoder
      Base64$Encoder)))


(def decoder (Base64/getDecoder))
(def encoder (Base64/getEncoder))
(def utf-8 "UTF-8")

(def bytes-class (class (.getBytes "")))

(defn bytes->string [^bytes b] (String. ^bytes b ^String utf-8))


(defn encode-bytes [bytes]
  (.encode ^Base64$Encoder encoder ^bytes bytes))


(defn encode [str] (bytes->string (encode-bytes (.getBytes ^String str))))


(defn decode-bytes [bytes]
  (.decode ^Base64$Decoder decoder ^bytes bytes))


(defn decode [str]
  (let [bts (decode-bytes (.getBytes ^String str))]

    (bytes->string bts)))
