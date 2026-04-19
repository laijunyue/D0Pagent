"""Decorators for namespace, tool, and toolset with auto-generated docstrings."""

import inspect
import re
import sys
import textwrap
from functools import wraps
from typing import Callable, Any
from pydantic import BaseModel, Field


def md_section(level: int, title: str, *content: str) -> str:
    """Generate markdown section with title and content."""
    lines = [f"{'#' * level} {title}", ""]
    lines.extend(content)
    return "\n".join(lines)


def md_code(code: str, lang: str = "python") -> str:
    """Generate markdown code block."""
    return f"```{lang}\n{code}\n```"


class DocModel(BaseModel):
    """Docstring metadata model."""
    description: str = ""
    signature: str = ""

    def get_short_description(self) -> str:
        """Get description without Example section."""
        return self.description.split('\n\n####')[0].strip()

    @classmethod
    def from_docstring(cls, docstring: str, fallback: str = "") -> "DocModel":
        """Parse docstring and create DocModel."""
        from docstring_parser import parse

        if not docstring:
            return cls(description=fallback)

        parsed = parse(docstring)
        parts = [p for p in [parsed.short_description, parsed.long_description] if p]
        return cls(description="\n\n".join(parts) or fallback)

    @classmethod
    def from_function(cls, func: Callable) -> "DocModel":
        """Parse function docstring and signature to create DocModel."""
        from docstring_parser import parse

        if not func.__doc__:
            return cls(description=func.__name__, signature=f"def {func.__name__}{inspect.signature(func)}")

        parsed = parse(func.__doc__)
        parts = [p for p in [parsed.short_description, parsed.long_description] if p]

        # Add Examples from meta as subsection
        for meta in parsed.meta:
            if type(meta).__name__ == 'DocstringExample' and meta.description:
                parts.append(f"#### Example\n\n{meta.description}")

        description = "\n\n".join(parts) if parts else func.__name__
        signature = f"def {func.__name__}{inspect.signature(func)}"
        return cls(description=description, signature=signature)

    def man(self, tool_name: str = "") -> str:
        """Generate documentation: description, signature, then example."""
        # Split description and example
        parts_split = self.description.split('\n\n####')
        short_desc = parts_split[0].strip()

        parts = []
        if tool_name:
            parts.append(md_section(1, tool_name, short_desc))
        else:
            parts.append(short_desc)

        if self.signature:
            parts.append(md_section(2, "Signature", md_code(self.signature)))

        # Add example if exists
        if len(parts_split) > 1:
            example_content = parts_split[1].split('\n\n', 1)[1] if '\n\n' in parts_split[1] else parts_split[1]
            parts.append(md_section(2, "Example", example_content.strip()))

        return "\n\n".join(parts)


class ToolModel(BaseModel):
    """Tool metadata model."""
    name: str
    func: Any = Field(exclude=True)
    docmodel: DocModel = Field(default_factory=DocModel)

    def man(self) -> str:
        return self.docmodel.man(self.name)


class ToolsetModel(BaseModel):
    """Toolset metadata model."""
    name: str
    obj: type | None = Field(default=None, exclude=True)
    tools: dict[str, ToolModel] = Field(default_factory=dict)
    docmodel: DocModel = Field(default_factory=DocModel)

    def man(self) -> str:
        sections = [md_section(1, self.name, self.docmodel.description), md_section(2, "tool")]
        for tool in self.tools.values():
            content = [tool.docmodel.get_short_description()]
            if tool.docmodel.signature:
                content.extend(["", md_code(tool.docmodel.signature)])
            sections.append(md_section(3, tool.name, *content))
        return "\n\n".join(sections)


class NamespaceModel(BaseModel):
    """Namespace metadata model."""
    name: str
    obj: Any = Field(default=None, exclude=True)
    toolsets: dict[str, ToolsetModel] = Field(default_factory=dict)
    tools: dict[str, ToolModel] = Field(default_factory=dict)
    docmodel: DocModel = Field(default_factory=DocModel)

    def man(self) -> str:
        sections = [md_section(1, self.name, self.docmodel.description)]

        sub_namespaces = [n for n in registry.list_namespaces()
                          if n.startswith(f"{self.name}.") and n.count('.') == self.name.count('.') + 1]
        if sub_namespaces:
            sections.append(md_section(2, "namespace"))
            for sub_ns in sub_namespaces:
                ns_model = registry.get_namespace(sub_ns)
                sections.append(md_section(3, sub_ns.split('.')[-1], ns_model.docmodel.description))

        if self.toolsets:
            sections.append(md_section(2, "toolset"))
            for ts in self.toolsets.values():
                sections.append(md_section(3, ts.name, ts.docmodel.description))

        if self.tools:
            sections.append(md_section(2, "tool"))
            for t in self.tools.values():
                sections.append(md_section(3, t.name, t.docmodel.description))

        return "\n\n".join(sections)


class Registry:
    """Global registry for namespace/toolset/tool hierarchy."""

    def __init__(self):
        self._namespaces: dict[str, NamespaceModel] = {}

    def register_namespace(self, name: str, obj: Any) -> None:
        if name in self._namespaces:
            return
        docmodel = DocModel.from_docstring(obj.__doc__ if obj else "", name)
        self._namespaces[name] = NamespaceModel(name=name, obj=obj, docmodel=docmodel)

    def register_toolset(self, namespace: str, name: str, obj: type) -> None:
        self.register_namespace(namespace, None)
        if name in self._namespaces[namespace].toolsets:
            return
        docmodel = DocModel.from_docstring(obj.__doc__ if obj else "", name)
        self._namespaces[namespace].toolsets[name] = ToolsetModel(name=name, obj=obj, docmodel=docmodel)

    def register_tool(self, namespace: str, toolset: str, name: str, func: Any) -> None:
        self.register_namespace(namespace, None)
        if toolset not in self._namespaces[namespace].toolsets:
            self.register_toolset(namespace, toolset, None)
        docmodel = getattr(func, '__docmodel__', DocModel(description=name))
        self._namespaces[namespace].toolsets[toolset].tools[name] = ToolModel(name=name, func=func, docmodel=docmodel)

    def register_namespace_tool(self, namespace: str, name: str, func: Any) -> None:
        self.register_namespace(namespace, None)
        docmodel = getattr(func, '__docmodel__', DocModel(description=name))
        self._namespaces[namespace].tools[name] = ToolModel(name=name, func=func, docmodel=docmodel)

    def get_namespace(self, name: str) -> NamespaceModel | None:
        return self._namespaces.get(name)

    def get_toolset(self, namespace: str, toolset: str) -> ToolsetModel | None:
        ns = self._namespaces.get(namespace)
        return ns.toolsets.get(toolset) if ns else None

    def get_tool(self, namespace: str, toolset: str, tool: str) -> ToolModel | None:
        ts = self.get_toolset(namespace, toolset)
        return ts.tools.get(tool) if ts else None

    def list_namespaces(self) -> list[str]:
        return list(self._namespaces.keys())

    def list_toolsets(self, namespace: str) -> list[str]:
        ns = self._namespaces.get(namespace)
        return list(ns.toolsets.keys()) if ns else []

    def list_tools(self, namespace: str, toolset: str) -> list[str]:
        ts = self.get_toolset(namespace, toolset)
        return list(ts.tools.keys()) if ts else []


registry = Registry()


def namespace(name: str | None = None):
    """Register namespace decorator."""
    frame = inspect.currentframe().f_back
    caller_module = frame.f_globals['__name__']
    name = name or caller_module.split('.')[-1]

    parent_ns = None
    if '.' in caller_module:
        parent_module = sys.modules.get(caller_module.rsplit('.', 1)[0])
        if parent_module:
            parent_ns = getattr(parent_module, '__namespace__', None)

    full_name = f"{parent_ns}.{name}" if parent_ns else name
    current_module = sys.modules[caller_module]
    current_module.__namespace__ = full_name
    registry.register_namespace(full_name, current_module)
    current_module.man = lambda: registry.get_namespace(full_name).man()

    return full_name


def tool(name: str | None = None, desc: str | None = None):
    """Register function as tool decorator."""
    def wrap(func):
        tool_name = name or func.__name__
        doc_model = DocModel(description=desc) if desc else DocModel.from_function(func)

        @wraps(func)
        async def async_wrapped(*a, **k):
            return await func(*a, **k)

        @wraps(func)
        def sync_wrapped(*a, **k):
            return func(*a, **k)

        wrapped = async_wrapped if inspect.iscoroutinefunction(func) else sync_wrapped
        wrapped.__tool_name__ = tool_name
        wrapped.__is_tool__ = True
        wrapped.__docmodel__ = doc_model
        wrapped.__doc__ = doc_model.man(tool_name)
        wrapped.man = lambda: doc_model.man(tool_name)

        if '.' not in func.__qualname__:
            module = sys.modules.get(func.__module__)
            if module and hasattr(module, '__namespace__'):
                registry.register_namespace_tool(module.__namespace__, tool_name, wrapped)

        return wrapped
    return wrap


def toolset(name: str | None = None):
    """Register class as toolset decorator."""
    def wrap(cls: type) -> type:
        tools = [n for n in dir(cls) if not n.startswith("_") and getattr(getattr(cls, n), "__is_tool__", False)]
        toolset_name = name or cls.__name__
        module = sys.modules[cls.__module__]
        ns = getattr(module, '__namespace__', None)

        if not ns:
            raise ValueError(f"Namespace not registered for {cls.__module__}. Call namespace() first.")

        cls.__toolset_name__ = toolset_name
        cls.__namespace__ = ns
        cls.__tools__ = tools
        cls.__docmodel__ = DocModel.from_docstring(cls.__doc__ or "", toolset_name)

        registry.register_toolset(ns, toolset_name, cls)
        for t in tools:
            registry.register_tool(ns, toolset_name, getattr(cls, t).__tool_name__, getattr(cls, t))

        cls.man = classmethod(lambda c: registry.get_toolset(ns, toolset_name).man())
        return cls
    return wrap
