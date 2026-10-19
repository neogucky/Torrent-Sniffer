import pytest

from app import database


def add_results(source, rows):
    with database.connect() as db:
        for index, (title, category, seeders) in enumerate(rows):
            db.execute(
                """INSERT INTO results(source_id, remote_query, title, category, seeders, details_url)
                   VALUES (?, 'Movie', ?, ?, ?, ?)""",
                (source["id"], title, category, seeders, f"/torrent/{index}"),
            )


def titles(client, **params):
    response = client.get("/api/results", params=params)
    assert response.status_code == 200, response.text
    return [row["title"] for row in response.json()]


def test_porn_filter_expands_to_related_words_in_titles_and_categories(client, source):
    add_results(
        source,
        [("Ordinary Movie", "Movies", 1)]
        + [(f"{term} Movie", "Movies", 20) for term in ["Porn", "XXX", "Sex", "Cum", "Vagina", "Penis"]]
        + [("Other Movie", "XXX", 30)],
    )
    assert titles(client, q="Movie", exclude=["porn"]) == ["Ordinary Movie"]
    # Removing the visible filter disables the implicit group too.
    assert len(titles(client, q="Movie")) == 8


@pytest.mark.parametrize("term", ["porn", "xxx", "sex", "cum", "vagina", "penis"])
def test_query_explicitly_allows_only_the_named_adult_word(client, source, term):
    add_results(
        source,
        [(f"{word} Movie", "Movies", 5) for word in ["porn", "xxx", "sex", "cum", "vagina", "penis"]],
    )
    assert titles(client, q=f"MOVIE {term.upper()}!", match_mode="any", exclude=["PoRn"]) == [f"{term} Movie"]


def test_sex_and_the_city_is_allowed_but_other_exclusions_still_apply(client, source):
    add_results(
        source,
        [
            ("Sex and the City", "TV Series", 10),
            ("Sex and the City XXX", "Movies", 100),
            ("Sex and the City Porn", "Movies", 200),
        ],
    )
    assert titles(client, q="SeX and the City", exclude=["porn"]) == ["Sex and the City"]
    # A separately configured exclusion is still explicit user intent.
    assert titles(client, q="Sex and the City", exclude=["porn", "sex"]) == []


def test_adult_exclusions_match_whole_words(client, source):
    add_results(
        source,
        [("Essex Movie", "Movies", 5), ("Circumstance Movie", "Movies", 4), ("Sex Movie", "Movies", 10)],
    )
    assert titles(client, q="Movie sexual", match_mode="any", exclude=["porn"]) == ["Essex Movie", "Circumstance Movie"]


def test_default_sort_is_most_seeders_first_and_can_be_changed(client, source):
    add_results(
        source,
        [("Unavailable Movie", "Movies", None), ("Less popular Movie", "Movies", 2), ("Popular Movie", "Movies", 50)],
    )
    assert titles(client, q="Movie") == ["Popular Movie", "Less popular Movie", "Unavailable Movie"]
    assert titles(client, q="Movie", sort="seeders_asc") == ["Less popular Movie", "Popular Movie", "Unavailable Movie"]
