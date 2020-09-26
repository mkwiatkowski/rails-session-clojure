(defproject lukaszkorecki/rails-session-clojure "0.3.0-SNAPSHOT"
  :description "Integration with Ruby on Rails encoded and signed session cookies. Maintained fork"
  :url "https://github.com/lukaszkorecki/rails-session-clojure"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :deploy-repositories [["releases" :clojars]
                        ["snapshots" :clojars]]
  :global-vars {*warn-on-reflection* true}
  :dependencies [[cheshire "5.10.0"]
                 [crypto-equality "1.0.0"]
                 [crypto-random "1.2.0"]
                 [org.clojure/clojure "1.10.1"]
                 [pandect "0.6.1"]])
