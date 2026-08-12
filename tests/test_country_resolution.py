import unittest

from country_resolution import country_aliases_to_code_2, iter_country_aliases


class CountryResolutionTests(unittest.TestCase):
    def test_country_aliases_include_dimension_values_and_overrides(self) -> None:
        aliases = country_aliases_to_code_2()

        self.assertEqual(aliases["russian federation"], "RU")
        self.assertEqual(aliases["russia"], "RU")
        self.assertEqual(aliases["united states"], "US")
        self.assertEqual(aliases["usa"], "US")
        self.assertEqual(aliases["u.s."], "US")
        self.assertEqual(aliases["united kingdom"], "GB")
        self.assertEqual(aliases["uk"], "GB")
        self.assertEqual(aliases["uae"], "AE")
        self.assertEqual(aliases["prc"], "CN")
        self.assertEqual(aliases["mainland china"], "CN")
        self.assertEqual(aliases["south korea"], "KR")
        self.assertEqual(aliases["north korea"], "KP")
        self.assertEqual(aliases["iran"], "IR")
        self.assertEqual(aliases["syria"], "SY")
        self.assertEqual(aliases["turkiye"], "TR")
        self.assertEqual(aliases["vietnam"], "VN")
        self.assertEqual(aliases["ivory coast"], "CI")

    def test_country_alias_iteration_prefers_longer_aliases_first(self) -> None:
        aliases = iter_country_aliases()
        alias_names = [alias for alias, _code in aliases]

        self.assertLess(alias_names.index("russian federation"), alias_names.index("russia"))
        self.assertLess(alias_names.index("united states"), alias_names.index("us"))
        self.assertLess(alias_names.index("mainland china"), alias_names.index("china"))
        self.assertLess(alias_names.index("saint kitts and nevis"), alias_names.index("saint kitts"))


if __name__ == "__main__":
    unittest.main()
