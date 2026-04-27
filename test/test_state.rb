require_relative "test_helper"
require "tmpdir"
require "fileutils"

class TestState < Minitest::Test
  def setup
    @tmpdir   = Dir.mktmpdir
    @path     = File.join(@tmpdir, "state.json")
    @pkg      = StackWatch::Package.new(name: "django", ecosystem: "PyPI", tier: "standard")
    @vuln_a   = { "id" => "CVE-2024-001", "summary" => "A" }
    @vuln_b   = { "id" => "CVE-2024-002", "summary" => "B" }
  end

  def teardown
    FileUtils.rm_rf(@tmpdir)
  end

  def test_load_missing_file_starts_fresh
    refute File.exist?(@path)
    state = StackWatch::State.load(@path)
    # No exception; empty state treats all vulns as new
    assert_equal [@vuln_a], state.diff(@pkg, [@vuln_a])
  end

  def test_diff_returns_new_vulns_when_state_empty
    state = StackWatch::State.load(@path)
    result = state.diff(@pkg, [@vuln_a, @vuln_b])
    assert_equal [@vuln_a, @vuln_b], result
  end

  def test_diff_excludes_seen_vulns
    state = StackWatch::State.load(fixture_path("state_v1.json"))
    django_pkg = StackWatch::Package.new(name: "django", ecosystem: "PyPI", tier: "critical")
    result = state.diff(django_pkg, [
      { "id" => "CVE-2024-27351" },   # already seen
      { "id" => "CVE-2024-99999" }    # new
    ])
    assert_equal 1, result.size
    assert_equal "CVE-2024-99999", result[0]["id"]
  end

  def test_diff_returns_empty_when_all_seen
    state = StackWatch::State.load(fixture_path("state_v1.json"))
    django_pkg = StackWatch::Package.new(name: "django", ecosystem: "PyPI", tier: "critical")
    assert_equal [], state.diff(django_pkg, [{ "id" => "CVE-2024-27351" }])
  end

  def test_mark_seen_then_diff_returns_empty
    state = StackWatch::State.load(@path)
    state.mark_seen(@pkg, [@vuln_a])
    assert_equal [], state.diff(@pkg, [@vuln_a])
  end

  def test_mark_seen_deduplicates
    state = StackWatch::State.load(@path)
    state.mark_seen(@pkg, [@vuln_a])
    state.mark_seen(@pkg, [@vuln_a])
    state.persist

    reloaded = StackWatch::State.load(@path)
    data     = JSON.parse(File.read(@path))
    assert_equal 1, data.dig("packages", "PyPI/django").size
  end

  def test_persist_writes_valid_json
    state = StackWatch::State.load(@path)
    state.mark_seen(@pkg, [@vuln_a])
    state.persist

    data = JSON.parse(File.read(@path))
    assert_equal 1, data["version"]
    assert_includes data.dig("packages", "PyPI/django"), "CVE-2024-001"
  end

  def test_persist_atomic_no_tmp_left
    state = StackWatch::State.load(@path)
    state.persist

    tmp_files = Dir.glob("#{@path}.tmp.*")
    assert_empty tmp_files
  end

  def test_load_corrupt_json_starts_fresh
    File.write(@path, "not json {{{{")
    state = StackWatch::State.load(@path)
    result = state.diff(@pkg, [@vuln_a])
    assert_equal [@vuln_a], result
  end
end
