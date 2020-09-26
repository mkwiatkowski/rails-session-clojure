(ns rails-session-clojure.core
  (:require
    [cheshire.core :as json]
    [clojure.string :as str]
    [crypto.equality :as crypto]
    [crypto.random :as random]
    [pandect.algo.sha1 :as pandect]
    [rails-session-clojure.base64 :as base64])
  (:import
    (javax.crypto
      Cipher
      SecretKeyFactory)
    (javax.crypto.spec
      IvParameterSpec
      PBEKeySpec
      SecretKeySpec)))


(defn disable-crypto-restriction!
  "Disable JCE restrictions to enable strong encryption. Call this function
  if crypto doesn't work despite correct settings.
  Note: applies only to Oracle's JVM."
  []
  (let [field (.getDeclaredField (Class/forName "javax.crypto.JceSecurity") "isRestricted")]
    (doto field
      (.setAccessible true)
      (.set nil false))))

;; Based on http://adambard.com/blog/3-wrong-ways-to-store-a-password/
(defn pbkdf2
  "Returns bytes array of the specified length derived from applying PBKDF2
  to the given key and salt.
  key           - (String) key/password
  salt          - (String) cryptographic salt
  size-in-bytes - (int) desired length of the result in bytes"
  [key salt size-in-bytes]
  ^bytes
  (let [iterations 1000
        key-size (* size-in-bytes 8)
        key-spec (PBEKeySpec. (.toCharArray  ^String key) (.getBytes ^String salt) iterations key-size)
        factory (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA1")]
    (.getEncoded (.generateSecret factory key-spec))))


(defn separate-data-and-padding [message]
  (str/split message #"--"))


(defn combine-data-and-padding [data padding]
  (str data #"--" padding))


(defn separate-and-decode [message]
  (map #(base64/decode-bytes (.getBytes ^String %)) (separate-data-and-padding message)))


(defn encode-and-combine [padding data]
  (apply combine-data-and-padding (map #(String. ^bytes (base64/encode-bytes %)) [data padding])))


(defn generate-random-iv []
  (random/bytes 16))


(defn verify-signature
  "Returns data section of the message if the signature is valid or nil otherwise.
  message - (String) message to be validated
  secret  - (byte[]) secret to be used during hashing"
  [message secret]
  ^String
  (let [[data received-digest] (separate-data-and-padding message)]
    (if (and data
             received-digest
             (crypto/eq? received-digest (pandect/sha1-hmac data secret)))
      (base64/decode data))))


(defn add-signature
  "Returns a base64-encoded message combined with its signature.
  secret  - (byte[]) secret to be used during hashing
  message - (String) message to generate signature for"
  [secret message]
  ^String
  (let [encoded-message (base64/encode message)
        signature (pandect/sha1-hmac encoded-message secret)]
    (combine-data-and-padding encoded-message signature)))


(defn json-parse-bytes [^bytes message]
  (json/parse-string (String. message "UTF-8")))


(defn json-generate-bytes [message]
  (.getBytes (json/generate-string message)))


(defn run-crypto
  "Returns crypted/decrypted message depending on mode. Raises an exception
  when unsuccessful.
  mode   - (int)    Cipher/ENCRYPT_MODE or Cipher/DECRYPT_MODE
  secret - (byte[]) encryption secret
  iv     - (byte[]) initialization vector
  data   - (byte[]) data to be en/de-crypted"
  [mode secret iv data]
  ^bytes
  (let [key-spec (SecretKeySpec. secret "AES")
        iv-spec  (IvParameterSpec. iv)
        cipher   (Cipher/getInstance "AES/CBC/PKCS5Padding")]
    (.init cipher (int mode) key-spec iv-spec)
    (.doFinal cipher data)))


(defn decrypt [secret iv data]
  (run-crypto Cipher/DECRYPT_MODE secret iv data))


(defn encrypt [secret iv data]
  (run-crypto Cipher/ENCRYPT_MODE secret iv data))


(def default-signature-salt "signed encrypted cookie")
(def default-encryption-salt "encrypted cookie")


(defn calculate-secrets
  "Returns signature and encryption secrets in a vector."
  ([secret-key-base]
   (calculate-secrets secret-key-base default-signature-salt default-encryption-salt))
  ([secret-key-base signature-salt encryption-salt]
   [(pbkdf2 secret-key-base signature-salt 64)
    (pbkdf2 secret-key-base encryption-salt 32)]))


(defn create-session-decryptor
  "Returns a function that when called will verify signature, decrypt a session
  string and deserialize the resulting json data into a map structure.

  secret-key-base - (String) value of secret_key_base usually found in config/secrets.yml
  signature-salt  - (String) value of 'config.action_dispatch.encrypted_cookie_salt'
  encryption-salt - (String) value of 'config.action_dispatch.encrypted_signed_cookie_salt'"
  [& config]
  (let [[signature-secret encryption-secret] (apply calculate-secrets config)]
    (fn [message]
      (try
        (if-let [verified-message (verify-signature message signature-secret)]
          (let [[data iv] (separate-and-decode verified-message)]
            (->> data
                 (decrypt encryption-secret iv)
                 (json-parse-bytes))))
        (catch java.lang.IllegalArgumentException _ nil)
        (catch java.security.InvalidAlgorithmParameterException _ nil)
        (catch javax.crypto.IllegalBlockSizeException _ nil)))))


(defn create-session-encryptor
  "Returns a function that when called will serialize session hash to json,
  encrypt and sign it.

  secret-key-base - (String) value of secret_key_base usually found in config/secrets.yml
  signature-salt  - (String) value of 'config.action_dispatch.encrypted_cookie_salt'
  encryption-salt - (String) value of 'config.action_dispatch.encrypted_signed_cookie_salt'"
  [& config]
  (let [[signature-secret encryption-secret] (apply calculate-secrets config)]
    (fn [message]
      (let [iv (generate-random-iv)]
        (->> message
             (json-generate-bytes)
             (encrypt encryption-secret iv)
             (encode-and-combine iv)
             (add-signature signature-secret))))))
