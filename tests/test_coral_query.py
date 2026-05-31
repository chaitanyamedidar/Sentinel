from sentinel.coral.query import macro_for_intent


def test_release_intent_maps_to_release_blockers():
    assert macro_for_intent("are we safe to release?") == "vw_release_blockers.sql"


def test_secret_intent_maps_to_credential_macro():
    assert macro_for_intent("show credential exposure") == "vw_credential_exposure.sql"


def test_workflow_intent_maps_to_workflow_macro():
    assert macro_for_intent("show workflow mutations") == "vw_workflow_mutations.sql"
