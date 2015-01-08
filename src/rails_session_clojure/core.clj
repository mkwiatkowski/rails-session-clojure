(ns rails-session-clojure.core
  (:import
   [javax.crypto.spec SecretKeySpec IvParameterSpec PBEKeySpec]
   [javax.crypto Cipher SecretKeyFactory])
  (:require
   [base64-clj.core :as base64]
   [cheshire.core :as json]
   [clojure.string :as str]
   [crypto.equality :as crypto]
   [pandect.core :as pandect]))

;; Based on http://adambard.com/blog/3-wrong-ways-to-store-a-password/
(defn- pbkdf2
  "Returns bytes array of the specified length derived from applying PBKDF2
  to the given key and salt.
  key           - (String) key/password
  salt          - (String) cryptographic salt
  size-in-bytes - (int) desired length of the result in bytes"
  [key salt size-in-bytes]
  ^bytes
  (let [iterations 1000
        key-size (* size-in-bytes 8)
        key-spec (PBEKeySpec. (.toCharArray key) (.getBytes salt) iterations key-size)
        factory (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA1")]
    (.getEncoded (.generateSecret factory key-spec))))

(defn- separate-data-and-padding [message]
  (str/split message #"--"))

(defn- verify-signature
  "Returns data section of the message if the signature is valid or nil otherwise.
  message - (String) message to be validated
  secret  - (byte[]) secret to be used during hashing"
  [message secret]
  ^String
  (let [[data received-digest] (separate-data-and-padding message)]
    (if (and data
             received-digest
             (crypto/eq? received-digest (pandect/sha1-hmac data secret)))
      (base64/decode data "ASCII"))))

;; Based on https://github.com/clavoie/lock-key
(defn- get-cipher
  "Returns an AES/CBC/PKCS5Padding Cipher which can be used to encrypt or decrypt a
  byte[], depending on the mode of the Cipher.
  mode     - (int) see https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
                   for available modes. Typically this will be either Cipher/ENCRYPT_MODE
                   or Cipher/DECRYPT_MODE.
  seed     - (String) the encryption seed / secret
  iv-bytes - (byte[]) the initialization vector"
  ^Cipher
  [mode seed iv-bytes]
  (let [key-spec (SecretKeySpec. seed "AES")
        iv-spec  (IvParameterSpec. iv-bytes)
        cipher   (Cipher/getInstance "AES/CBC/NoPadding")]
    (.init cipher (int mode) key-spec iv-spec)
    cipher))

(defn- run-crypto
  "Returns crypted/decrypted message depending on mode. Returns nil when unsuccessful.
  mode    - (int)    Cipher/ENCRYPT_MODE or Cipher/DECRYPT_MODE
  message - (String) message to be decrypted
  secret  - (byte[]) encryption secret"
  [mode message secret]
  ^String
  (try
    (let [[data iv] (map #(base64/decode-bytes (.getBytes %)) (separate-data-and-padding message))
          cipher (get-cipher mode secret iv)]
      (String. (.doFinal cipher data 0 (count data))))
    (catch java.lang.IllegalArgumentException _ nil)
    (catch java.security.InvalidAlgorithmParameterException _ nil)
    (catch javax.crypto.IllegalBlockSizeException _ nil)))

(def default-signature-salt "signed encrypted cookie")
(def default-encryption-salt "encrypted cookie")

(defn- create-session-handling-function
  "Returns a function that will be able to handle session data: either encrypt
  or decrypt it, depending on the callback.
  The callback will be called with a message, signature secret and encryption
  secret."
  ([callback secret-key-base]
   (create-session-handling-function callback secret-key-base default-signature-salt default-encryption-salt))
  ([callback secret-key-base signature-salt encryption-salt]
   (let [signature-secret (pbkdf2 secret-key-base signature-salt 64)
         encryption-secret (pbkdf2 secret-key-base encryption-salt 32)]
     (fn [message]
       (callback message signature-secret encryption-secret)))))

(defn create-session-decryptor [& args]
  "Returns a function that when called will decode an encoded session string.

  secret-key-base - (String) value of secret_key_base usually found in config/secrets.yml
  signature-salt  - (String) value of 'config.action_dispatch.encrypted_cookie_salt'
  encryption-salt - (String) value of 'config.action_dispatch.encrypted_signed_cookie_salt'"
  (apply create-session-handling-function
         (fn [message signature-secret encryption-secret]
           (if-let [verified-message (verify-signature message signature-secret)]
             (if-let [decrypted-message (run-crypto Cipher/DECRYPT_MODE verified-message encryption-secret)]
               (json/parse-string decrypted-message))))
         args))
