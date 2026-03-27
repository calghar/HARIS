from src.models.scan_context import ScanContext


class TestScanContextDefaults:
    def test_default_creation(self) -> None:
        ctx = ScanContext()
        assert ctx.detected_technologies == []
        assert ctx.discovered_urls == []
        assert ctx.open_ports == []
        assert ctx.server_headers == {}


class TestAddTechnologies:
    def test_add_single_technology(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies(["nginx"])
        assert ctx.detected_technologies == ["nginx"]

    def test_add_multiple_technologies(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies(["nginx", "php", "wordpress"])
        assert "nginx" in ctx.detected_technologies
        assert "php" in ctx.detected_technologies
        assert "wordpress" in ctx.detected_technologies

    def test_deduplication_case_insensitive(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies(["Nginx"])
        ctx.add_technologies(["nginx"])
        ctx.add_technologies(["NGINX"])
        assert len(ctx.detected_technologies) == 1
        assert ctx.detected_technologies[0] == "nginx"

    def test_preserves_first_case(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies(["WordPress"])
        ctx.add_technologies(["wordpress"])
        assert ctx.detected_technologies == ["wordpress"]

    def test_multiple_additions_cumulative(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies(["nginx"])
        ctx.add_technologies(["php"])
        ctx.add_technologies(["wordpress"])
        assert len(ctx.detected_technologies) == 3

    def test_empty_list_noop(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies([])
        assert ctx.detected_technologies == []


class TestAddUrls:
    def test_add_single_url(self) -> None:
        ctx = ScanContext()
        ctx.add_urls(["https://example.com/page"])
        assert ctx.discovered_urls == ["https://example.com/page"]

    def test_add_multiple_urls(self) -> None:
        ctx = ScanContext()
        ctx.add_urls(
            [
                "https://example.com/page1",
                "https://example.com/page2",
                "https://example.com/page3",
            ]
        )
        assert len(ctx.discovered_urls) == 3

    def test_deduplication_exact_match(self) -> None:
        ctx = ScanContext()
        ctx.add_urls(["https://example.com/page"])
        ctx.add_urls(["https://example.com/page"])
        ctx.add_urls(["https://example.com/page"])
        assert len(ctx.discovered_urls) == 1

    def test_case_sensitive_urls(self) -> None:
        ctx = ScanContext()
        ctx.add_urls(["https://example.com/Page"])
        ctx.add_urls(["https://example.com/page"])
        assert len(ctx.discovered_urls) == 2

    def test_multiple_additions_cumulative(self) -> None:
        ctx = ScanContext()
        ctx.add_urls(["https://example.com/page1"])
        ctx.add_urls(["https://example.com/page2"])
        assert len(ctx.discovered_urls) == 2

    def test_empty_list_noop(self) -> None:
        ctx = ScanContext()
        ctx.add_urls([])
        assert ctx.discovered_urls == []


class TestMixedOperations:
    def test_independent_collections(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies(["nginx", "php"])
        ctx.add_urls(["https://example.com/page"])
        ctx.open_ports.append("443")
        ctx.server_headers["server"] = "nginx"

        assert len(ctx.detected_technologies) == 2
        assert len(ctx.discovered_urls) == 1
        assert len(ctx.open_ports) == 1
        assert len(ctx.server_headers) == 1
