"""`taema help TOPIC` and `--help` examples (issue #83)."""

import io
import unittest
from contextlib import redirect_stdout

from taema.cli import fast, framework
from taema.cli import help_topics
from taema.cli import registry


class HelpTopics(unittest.TestCase):
    def test_all_ten_topics_listed(self):
        listing = help_topics.listing()
        for topic in (
            "modes",
            "learning",
            "veto",
            "ladder",
            "memory",
            "units",
            "agent",
            "profiles",
            "privacy",
            "safety",
        ):
            self.assertIn(topic, listing)

    def test_each_topic_has_body(self):
        for topic in help_topics.names():
            with self.subTest(topic=topic):
                self.assertTrue(help_topics.text(topic).strip())

    def test_unknown_topic_is_none(self):
        self.assertIsNone(help_topics.text("nope"))

    def test_help_command_lists_and_shows(self):
        from taema.cli import commands
        from types import SimpleNamespace

        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(commands.cmd_help(SimpleNamespace(topic=None)), 0)
        self.assertIn("modes", out.getvalue())
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(commands.cmd_help(SimpleNamespace(topic="veto")), 0)
        self.assertIn("veto", out.getvalue().lower())

    def test_help_unknown_topic_fails(self):
        from taema.cli import commands
        from types import SimpleNamespace

        self.assertEqual(commands.cmd_help(SimpleNamespace(topic="nope")), 1)


class HelpExamples(unittest.TestCase):
    def test_top_level_help_ends_with_examples(self):
        text = fast.help_text()
        self.assertIn("Examples:", text)
        self.assertGreaterEqual(text.strip().split("Examples:")[1].count("taema "), 2)

    def test_every_command_help_ends_with_two_examples(self):
        missing = []
        for spec in registry.COMMANDS:
            if spec.get("hidden"):
                continue
            for child in (spec.get("children") or ()) + (None,):
                name = spec["name"] + (" " + child["name"] if child else "")
                if len(framework._examples_for(name)) < 2:
                    missing.append(name)
        self.assertEqual(missing, [])

    def test_argparse_epilogs_render(self):
        import argparse as _ap

        parser = framework._parser()
        for argv in (["status"], ["learn", "export"], ["bug-report"]):
            with self.subTest(argv=argv):
                sub = argv[0]
                help_text = None
                for action in parser._actions:
                    if isinstance(action, _ap._SubParsersAction):
                        subparser = action.choices.get(sub)
                        if subparser is not None and len(argv) == 1:
                            help_text = subparser.format_help()
                        elif subparser is not None:
                            for subaction in subparser._actions:
                                if isinstance(subaction, _ap._SubParsersAction):
                                    help_text = subaction.choices[argv[1]].format_help()
                self.assertIsNotNone(help_text)
                self.assertIn("Examples:", help_text)
