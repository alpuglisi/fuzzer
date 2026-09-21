"""Tests proving the `patterns/` provenance-corpus scaffold's shape works
end to end (T-LAB0.8 scaffold; full corpus authoring is a separate,
human-supervised follow-up — see lab/patterns/README.md).

No new `fuzzlab.labgen` module is needed for this: it is a data-shape check
over lab/patterns/*, using the same jsonschema-validation pattern as
fuzzlab.labels.contract.
"""

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

CARDS_DIR = Path("lab/patterns/cards")
PROVENANCE_PATH = Path("lab/patterns/provenance.yaml")
TAXONOMY_PATH = Path("lab/patterns/taxonomy/classes-v1.yaml")
CARD_SCHEMA_PATH = Path("lab/schemas/pattern_card.schema.json")
EXAMPLE_MANIFEST_PATH = Path("lab/manifests/example_phase0_scaffold.yaml")


def _card_schema():
    return json.loads(CARD_SCHEMA_PATH.read_text("utf-8"))


def _cards():
    return {p.stem: yaml.safe_load(p.read_text("utf-8")) for p in sorted(CARDS_DIR.glob("pc-*.yaml"))}


def _taxonomy_class_ids():
    data = yaml.safe_load(TAXONOMY_PATH.read_text("utf-8"))
    return {c["id"] for c in data["classes"]}


def _provenance():
    return yaml.safe_load(PROVENANCE_PATH.read_text("utf-8"))


def _manifest_cell_ids():
    data = yaml.safe_load(EXAMPLE_MANIFEST_PATH.read_text("utf-8"))
    return {c["cell_id"] for c in data["cells"]}


def test_at_least_two_example_cards_exist():
    cards = _cards()
    assert 2 <= len(cards) <= 3, "brief calls for 2-3 example cards, not a full corpus"


@pytest.mark.parametrize("name,card", list(_cards().items()))
def test_each_card_validates_against_schema(name, card):
    jsonschema.validate(card, _card_schema())


def test_card_ids_are_unique_and_match_filenames():
    cards = _cards()
    for stem, card in cards.items():
        assert card["id"] == stem


def test_every_card_class_is_in_the_taxonomy():
    class_ids = _taxonomy_class_ids()
    for _, card in _cards().items():
        assert card["class"] in class_ids


def test_plausible_confidence_cards_carry_notes():
    for _, card in _cards().items():
        if card["confidence"] == "plausible":
            assert card.get("notes"), f"{card['id']}: plausible confidence requires a rationale in notes"


def test_provenance_card_ids_all_exist():
    card_ids = {card["id"] for card in _cards().values()}
    for cell_id, refs in _provenance().items():
        for ref in refs:
            assert ref in card_ids, f"provenance.yaml references unknown card {ref!r} for cell {cell_id!r}"


def test_provenance_cell_ids_resolve_to_the_example_manifest():
    manifest_ids = _manifest_cell_ids()
    for cell_id in _provenance():
        assert cell_id in manifest_ids, f"provenance.yaml references unknown cell_id {cell_id!r}"


def test_manifest_carries_no_provenance_field():
    """Addendum A: the manifest the verdict engine reads carries no card
    reference at all — provenance is a separate, one-directional index."""
    data = yaml.safe_load(EXAMPLE_MANIFEST_PATH.read_text("utf-8"))
    for cell in data["cells"]:
        assert "id_ref" not in cell
        assert "pattern" not in cell
        assert "card_id" not in cell
