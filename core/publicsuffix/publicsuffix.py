"""Public Suffix List module for Python.
"""

import codecs
import os.path

class PublicSuffixList(object):
	def __init__(self, input_file=None):
		"""Reads and parses public suffix list.
		
		input_file is a file object or another iterable that returns
		lines of a public suffix list file. If input_file is None, an
		UTF-8 encoded file named "publicsuffix.txt" in the same
		directory as this Python module is used.
		
		The file format is described at http://publicsuffix.org/list/
		"""

		if input_file is None:
			input_path = os.path.join(os.path.dirname(__file__), 'publicsuffix.txt')
			input_file = codecs.open(input_path, "r", "utf8")

		root = self._build_structure(input_file)
		self.root = self._simplify(root)

	def _find_node(self, parent, parts):
		if not parts:
			return parent

		if len(parent) == 1:
			parent.append({})

		assert len(parent) == 2
		negate, children = parent

		child = parts.pop()

		child_node = children.get(child, None)

		if not child_node:
			children[child] = child_node = [0]

		return self._find_node(child_node, parts)

	def _add_rule(self, root, rule):
		if rule.startswith('!'):
			negate = 1
			rule = rule[1:]
		else:
			negate = 0

		parts = rule.split('.')
		self._find_node(root, parts)[0] = negate

	def _simplify(self, node):
		if len(node) == 1:
			return node[0]

		return (node[0], dict((k, self._simplify(v)) for (k, v) in node[1].items()))

	def _build_structure(self, fp):
		root = [0]

		for line in fp:
			line = line.strip()
			if line.startswith('//') or not line:
				continue

			self._add_rule(root, line.split()[0].lstrip('.'))

		return root

	def _lookup_node(self, matches, depth, parent, parts):
		if parent in (0, 1):
			negate = parent
			children = None
		else:
			negate, children = parent

		matches[-depth] = negate

		if depth < len(parts) and children:
			for name in ('*', parts[-depth]):
				child = children.get(name, None)
				if child is not None:
					self._lookup_node(matches, depth+1, child, parts)

	def get_public_suffix(self, domain):
		"""get_public_suffix("www.example.com") -> "example.com"

		Calling this function with a DNS name will return the
		public suffix for that name.

		Note that for internationalized domains the list at
		http://publicsuffix.org uses decoded names, so it is
		up to the caller to decode any Punycode-encoded names.
		"""

		parts = domain.lower().lstrip('.').split('.')
		hits = [None] * len(parts)

		self._lookup_node(hits, 1, self.root, parts)

		for i, what in enumerate(hits):
			if what is not None and what == 0:
				return '.'.join(parts[i:])
