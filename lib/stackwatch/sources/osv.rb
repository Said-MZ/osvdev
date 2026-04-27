module StackWatch
  module Sources
    class OSV
      BASE_URI    = URI("https://api.osv.dev/v1/querybatch")
      TIMEOUT_SEC = 15

      def initialize(packages)
        @packages = packages
      end

      def fetch_all
        return {} if @packages.empty?

        body = post_batch(build_payload)
        parse_response(body)
      end

      private

      def build_payload
        queries = @packages.map do |pkg|
          { "package" => { "name" => pkg.name, "ecosystem" => pkg.ecosystem } }
        end
        { "queries" => queries }
      end

      def post_batch(payload)
        http = Net::HTTP.new(BASE_URI.host, BASE_URI.port)
        http.use_ssl      = true
        http.open_timeout = TIMEOUT_SEC
        http.read_timeout = TIMEOUT_SEC

        req = Net::HTTP::Post.new(BASE_URI.path)
        req["Content-Type"] = "application/json"
        req.body = JSON.generate(payload)

        res = http.request(req)
        raise OSVError, "OSV API error #{res.code}: #{res.body}" unless res.is_a?(Net::HTTPSuccess)

        JSON.parse(res.body)
      rescue Net::OpenTimeout, Net::ReadTimeout => e
        raise OSVError, "OSV API timeout: #{e.message}"
      rescue JSON::ParserError => e
        raise OSVError, "OSV API returned invalid JSON: #{e.message}"
      end

      def parse_response(body)
        results = body.fetch("results", [])
        @packages.zip(results).each_with_object({}) do |(pkg, result), map|
          vulns = result&.fetch("vulns", []) || []
          map[pkg] = vulns.map { |v| normalize(v) }
        end
      end

      def normalize(raw)
        {
          "id"         => raw["id"],
          "summary"    => (raw["summary"] || raw["details"].to_s.slice(0, 200)).to_s.strip,
          "cvss_score" => extract_cvss(raw),
          "affected"   => extract_affected(raw),
          "fixed"      => extract_fixed(raw),
          "url"        => "https://osv.dev/vulnerability/#{raw["id"]}"
        }
      end

      def extract_cvss(raw)
        raw.dig("severity")
           &.find { |s| s["type"] == "CVSS_V3" }
           &.dig("score") ||
          raw.dig("database_specific", "cvss", "score") ||
          "N/A"
      end

      def extract_affected(raw)
        events = raw.dig("affected", 0, "ranges", 0, "events") || []
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
