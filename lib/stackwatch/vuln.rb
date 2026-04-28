module StackWatch
  Vuln = Struct.new(:id, :summary, :cvss_score, :affected, :fixed, :url, keyword_init: true) do
    class << self
      def from_osv(raw)
        id = raw["id"]
        new(
          id:         id,
          summary:    extract_summary(raw),
          cvss_score: extract_cvss(raw),
          affected:   extract_affected(raw),
          fixed:      extract_fixed(raw),
          url:        "https://osv.dev/vulnerability/#{id}"
        )
      end

      private

      def extract_summary(raw)
        (raw["summary"] || raw["details"].to_s.slice(0, 200)).to_s.strip
      end

      def extract_cvss(raw)
        raw.dig("severity")
           &.find { |s| s["type"] == "CVSS_V3" }
           &.dig("score") ||
          raw.dig("database_specific", "cvss", "score") ||
          "N/A"
      end

      def extract_affected(raw)
        events    = raw.dig("affected", 0, "ranges", 0, "events") || []
        introduced = events.select { |e| e["introduced"] }.map { |e| ">=#{e["introduced"]}" }
        introduced.empty? ? "unknown" : introduced.join(", ")
      end

      def extract_fixed(raw)
        events = raw.dig("affected", 0, "ranges", 0, "events") || []
        events.find { |e| e["fixed"] }&.dig("fixed")
      end
    end
  end
end
