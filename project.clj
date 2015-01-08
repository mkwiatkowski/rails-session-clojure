(defproject rails-session-clojure "0.1.0-SNAPSHOT"
  :description "Integration with Ruby on Rails encoded and signed session cookies"
  :url "https://github.com/mkwiatkowski/rails-session-clojure"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[base64-clj "0.1.1"]
                 [cheshire "5.4.0"]
                 [crypto-equality "1.0.0"]
                 [org.clojure/clojure "1.6.0"]
                 [pandect "0.4.1"]])
