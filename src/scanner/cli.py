"""CLI entry point for the prompt injection scanner."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from scanner.orchestrator import Orchestrator


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scan-skills",
        description="Scan skill files for prompt injection threats.",
    )
    parser.add_argument(
        "--path",
        default="./skills",
        help="Directory containing skill files to scan (default: ./skills)",
    )
    parser.add_argument(
        "--output",
        default="./report",
        help="Output directory for reports (default: ./report)",
    )
    parser.add_argument(
        "--stage",
        choices=["1", "2", "full", "full-llm"],
        default="full",
        help=(
            "1=rules only; 2=LLM only; full=rules then LLM only when rules are not CLEAN; "
            "full-llm=rules then LLM for every skill (default: full)"
        ),
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "all"],
        default="all",
        help="Minimum severity level to report (default: all)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "md", "both"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=5,
        help="Number of skills per LLM batch in Stage 2 (default: 5)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=3,
        help="Number of concurrent LLM requests (default: 3)",
    )
    parser.add_argument(
        "--resume",
        metavar="SCAN_ID",
        default=None,
        help="Resume a previously interrupted scan by its scan ID",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="LLM model name for Stage 2 (default: glm-4-plus)",
    )
    parser.add_argument(
        "--api-base",
        default=None,
        help="OpenAI-compatible API base URL (default: Volcano Engine ARK)",
    )
    parser.add_argument(
        "--api-key-env",
        default="ARK_API_KEY",
        help="Environment variable name for API key (default: ARK_API_KEY)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Shorthand for --log-level DEBUG",
    )
    parser.add_argument(
        "--report-all-skills",
        action="store_true",
        help="Output per-skill report for every skill: with findings -> threats/, no findings -> clean/ (default: only skills with findings get threats/<id>.json)",
    )
    parser.add_argument(
        "--ti-api-key",
        default=None,
        help="QAX TI API key (default: read from TI_API_KEY env var)",
    )
    ti_group = parser.add_mutually_exclusive_group()
    ti_group.add_argument(
        "--enable-ti",
        action="store_true",
        default=True,
        help="Enable threat intelligence IOC lookup (default: enabled)",
    )
    ti_group.add_argument(
        "--disable-ti",
        action="store_true",
        help="Disable threat intelligence IOC lookup",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    log_level = "DEBUG" if args.verbose else args.log_level
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    # Suppress noisy third-party debug logs
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)

    enable_ti = args.enable_ti and not args.disable_ti
    ti_api_key = args.ti_api_key or os.environ.get("TI_API_KEY")

    orchestrator = Orchestrator(
        skills_dir=args.path,
        output_dir=args.output,
        stage=args.stage,
        severity_filter=args.severity,
        batch_size=args.batch_size,
        concurrency=args.concurrency,
        resume_scan_id=args.resume,
        model=args.model,
        api_base=args.api_base,
        api_key_env=args.api_key_env,
        report_all_skills=args.report_all_skills,
        ti_api_key=ti_api_key,
        enable_qax_ti=enable_ti,
    )
    orchestrator.run()


if __name__ == "__main__":
    main()
