(ns rails-session-clojure.core-test
  (:require [clojure.test :refer :all]
            [rails-session-clojure.core :refer :all]))

(set! *warn-on-reflection* true)

(deftest test-create-session-encryptor
  (let [secret-key-base "abcd"
        encrypt-session (create-session-encryptor secret-key-base)]

    (testing "encrypt-session successfully encrypts hash into a string"
      (let [value (encrypt-session {"some" "data"})]
        (is (= (string? value)))
        (is (= 110 (count value)))))))

(deftest test-create-session-decryptor
  (let [secret-key-base "abcd"
        decrypt-session (create-session-decryptor secret-key-base)]

    (testing "decrypt-session successfully decrypts value into a hash"
      ;; typical rails session
      (is (= {"session_id" "cddf4f5a44da3f627fd186d3fc47a7ef",
              "foo" "bar",
              "_csrf_token" "6qbIbpxXn8sZnGSCV7SgvX+0lhzUXS0J51goFX6mJxY="}
             (decrypt-session "akhkL2pqZ1haaDl2Z2YyZFFLMDdQU0dsYlRqbEE2WG83N2VPU0Fhc2JNSkZvZys5d2Z2ODVGd3B4NDV5WVVLeFhQaVcwRGZnaTI1NHFwRzJER3pJZWJ0eXJhRlRSYWVNNjlaODRsWWdaRXM0Z1NLcXE4NUdGTG41YjU3MDNvTVhXWGZ2UDllVTF5Y3RLaUFyN01KZ3g5NW5DN2hjNnNxVzJWekRJN3pvM2lVPS0tN2JGWXFlOEI2TUU2VmdUTVR1Q2NrQT09--ee596f4baa5e48b5236c5d06331105ce9800302b"))))

    (testing "decrypt-session returns nil when value is bogus"
      (is (nil? (decrypt-session "notvalid"))))

    (testing "decrypt-session returns nil when verification fails"
      (is (nil? (decrypt-session "invaliddata--invalidpadding"))))

    (testing "decrypt-session returns nil when base64 fails to decode verified message"
      ;; fails to decode data
      (is (nil? (decrypt-session "invaliddata1--586e8d0d9eae566413d584ee3399b3a4fa4ce515"))))

    (testing "decrypt-session returns nil when decryption fails"
      ;; decodes to "test--test" which has too short iv
      (is (nil? (decrypt-session "dGVzdC0tdGVzdA==--103e09233c0d72ebc9d91fd57374ce786b46c3d4"))))

    (testing "decrypt-session returns nil when decryption fails"
      ;; iv decodes on second pass to "itissixteenbytes", but fails on decrypting
      (is (nil? (decrypt-session "dGVzdC0tYVhScGMzTnBlSFJsWlc1aWVYUmxjdz09--9cea6add243a54f9390dd780b94024464ab37c73"))))))

(deftest test-encrypt-decrypt-interaction
  (let [secret-key-base "super secret"
        encrypt (create-session-encryptor secret-key-base)
        decrypt (create-session-decryptor secret-key-base)
        value   {"string" "value", "number" 42, "array" [1 2]}]
    (testing "decrypt should successfully decrypt what encrypt encrypted"
      (is (= value (decrypt (encrypt value)))))))
