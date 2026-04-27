module StackWatch
  class State
    CURRENT_VERSION = 1

    def self.load(path)
      new(path: path).tap(&:read)
    end

    def initialize(path:)
      @path = path
      @data = empty_state
    end

    def read
      return unless File.exist?(@path)

      raw = JSON.parse(File.read(@path))
      @data = migrate(raw)
    rescue JSON::ParserError => e
      warn "StackWatch: corrupt state file at #{@path}, starting fresh (#{e.message})"
      @data = empty_state
    end

    def diff(package, vulns)
      seen = Set.new(@data.dig("packages", package_key(package)) || [])
      vulns.reject { |v| seen.include?(v["id"]) }
    end

    def mark_seen(package, vulns)
      key = package_key(package)
      @data["packages"][key] ||= []
      new_ids = vulns.map { |v| v["id"] }
      @data["packages"][key] = (@data["packages"][key] + new_ids).uniq.sort
    end

    def persist
      @data["updated_at"] = Time.now.utc.iso8601
      tmp = "#{@path}.tmp.#{Process.pid}"
      File.write(tmp, JSON.pretty_generate(@data))
      File.rename(tmp, @path)
    end

    private

    def package_key(package)
      "#{package.ecosystem}/#{package.name}"
    end

    def empty_state
      { "version" => CURRENT_VERSION, "updated_at" => nil, "packages" => {} }
    end

    def migrate(raw)
      return empty_state unless raw.is_a?(Hash)

      raw["version"]  ||= CURRENT_VERSION
      raw["packages"] ||= {}
      raw
    end
  end
end
