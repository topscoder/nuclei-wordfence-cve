import unittest
from src.lib.wordfence_api_parser import WordfenceAPIParser


class TestWordfenceAPIParser(unittest.TestCase):

    def test_get_affected_version_all_but_to_version(self):

        parser = WordfenceAPIParser()

        testcase = {
            "from_version": "*",
            "from_inclusive": "true",
            "to_version": "0.6.1",
            "to_inclusive": "false"
        }

        expected_result = "'< 0.6.1'"

        result = parser.get_affected_version(testcase)
        self.assertEqual(expected_result, result)

    def test_get_affected_version_including_to_version(self):

        parser = WordfenceAPIParser()

        testcase = {
            "from_version": "*",
            "from_inclusive": "true",
            "to_version": "1.8.1",
            "to_inclusive": "true"
        }

        expected_result = "'<= 1.8.1'"

        result = parser.get_affected_version(testcase)
        self.assertEqual(expected_result, result)

    def test_get_affected_version_four_positioned_version_number(self):
        parser = WordfenceAPIParser()

        testcase = {
            "from_version": "*",
            "from_inclusive": "true",
            "to_version": "1.4.6.2",
            "to_inclusive": "true"
        }

        expected_result = "'<= 1.4.6.2'"

        result = parser.get_affected_version(testcase)
        self.assertEqual(expected_result, result)

    def test_get_affected_version_two_positioned_version_number(self):
        parser = WordfenceAPIParser()

        testcase = {
            "from_version": "*",
            "from_inclusive": "true",
            "to_version": "5.0",
            "to_inclusive": "false"
        }

        expected_result = "'< 5.0'"

        result = parser.get_affected_version(testcase)
        self.assertEqual(expected_result, result)

    def test_get_affected_version_from_major_to_minor_version_number(self):
        parser = WordfenceAPIParser()

        testcase = {
            "from_version": "3.7",
            "from_inclusive": "true",
            "to_version": "3.7.4",
            "to_inclusive": "true"
        }

        expected_result = "'>= 3.7', '<= 3.7.4'"

        result = parser.get_affected_version(testcase)
        self.assertEqual(expected_result, result)

    def test_get_affected_version_single_version_number(self):
        parser = WordfenceAPIParser()

        testcase = {
            "from_version": "4.0",
            "from_inclusive": "true",
            "to_version": "4.0",
            "to_inclusive": "true"
        }

        expected_result = "'4.0'"

        result = parser.get_affected_version(testcase)
        self.assertEqual(expected_result, result)
