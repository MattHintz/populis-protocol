from __future__ import annotations

from a5_roster_candidate_fixture_cases import build_fixture, fixture_destination, write_fixture


def main() -> None:
    dest = write_fixture()
    print(f"wrote fixture to {dest}")


if __name__ == "__main__":
    main()
