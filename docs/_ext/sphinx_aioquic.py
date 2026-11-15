import dataclasses
import inspect

from docutils import nodes
from docutils.parsers.rst import Directive
from docutils.statemachine import StringList
from sphinx.pycode import ModuleAnalyzer
from sphinx.util.inspect import stringify_signature


class AioquicTransmit(Directive):
    def run(self):
        content = StringList(
            [
                ".. note::",
                "    After calling this method you need to call the QUIC connection "
                ":meth:`~aioquic.quic.connection.QuicConnection.datagrams_to_send` "
                "method to retrieve data which needs to be sent over the network. "
                "If you are using the :doc:`asyncio API <asyncio>`, calling the "
                ":meth:`~aioquic.asyncio.QuicConnectionProtocol.transmit` method "
                "will do it for you.",
            ]
        )
        node = nodes.paragraph()
        self.state.nested_parse(content, 0, node)
        return [node]


def hide_undocumented_fields(
    app, what, name, obj, options, signature, return_annotation
):
    """
    Leave the fields of a dataclass which have no docstring, and are therefore
    internal, out of its signature.
    """
    if what != "class" or not dataclasses.is_dataclass(obj):
        return None

    attr_docs = ModuleAnalyzer.for_module(obj.__module__).find_attr_docs()
    full_signature = inspect.signature(obj)
    parameters = [
        parameter
        for parameter in full_signature.parameters.values()
        if (obj.__qualname__, parameter.name) in attr_docs
    ]
    if len(parameters) == len(full_signature.parameters):
        return None

    return (
        stringify_signature(
            full_signature.replace(parameters=parameters), show_annotation=False
        ),
        None,
    )


def setup(app):
    app.add_directive("aioquic_transmit", AioquicTransmit)
    # Run before sphinx_autodoc_typehints, which would otherwise provide the
    # signature.
    app.connect("autodoc-process-signature", hide_undocumented_fields, priority=400)

    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
