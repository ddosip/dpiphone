"""Режимы запуска: какие тесты движка идут в каждом и какие разделы отчёта у него есть."""

MODE_TESTS = {"quick": "0123", "full": "01235", "sni": "34"}

# Разделы короткого отчёта по режимам (порядок вывода задаёт summary.py).
MODE_SECTIONS = {
    "quick": ("net", "dns", "domains", "tcp"),
    "full": ("net", "dns", "domains", "tcp", "telegram"),
    "sni": ("tcp", "sni"),
}
