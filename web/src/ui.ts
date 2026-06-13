// Tiny DOM + component helpers. The look (colors, font, hairlines, radius) lives in
// index.html's CSS, matching FileKey's Clean Minimal system. These build the markup.

type Attrs = Record<string, string | number | boolean | undefined>;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === "class") node.className = String(v);
    else if (k === "text") node.textContent = String(v);
    else node.setAttribute(k, String(v));
  }
  for (const c of children) node.append(c);
  return node;
}

export function clear(node: HTMLElement): void {
  node.replaceChildren();
}

/** A centered content card — the unit every Drop step renders into. */
export function card(children: (Node | string)[]): HTMLElement {
  return el("div", { class: "card" }, children);
}

export function h(title: string): HTMLElement {
  return el("h1", { class: "step-title", text: title });
}

export function p(textContent: string, cls = "muted"): HTMLElement {
  return el("p", { class: cls, text: textContent });
}

export function primaryButton(label: string, onClick: () => void): HTMLButtonElement {
  const b = el("button", { class: "btn btn-primary", type: "button" }, [label]);
  b.addEventListener("click", onClick);
  return b;
}

export function ghostButton(label: string, onClick: () => void): HTMLButtonElement {
  const b = el("button", { class: "btn btn-ghost", type: "button" }, [label]);
  b.addEventListener("click", onClick);
  return b;
}

export function field(labelText: string, input: HTMLElement): HTMLElement {
  return el("label", { class: "field" }, [el("span", { class: "field-label", text: labelText }), input]);
}

export function textInput(attrs: Attrs = {}): HTMLInputElement {
  return el("input", { class: "input", ...attrs });
}

/** A selectable monospace block — for the `fkey…` link the receiver shares. */
export function monoBox(value: string): HTMLElement {
  return el("div", { class: "mono-box", text: value });
}

export function note(textContent: string, kind: "info" | "error" | "ok" = "info"): HTMLElement {
  return el("div", { class: `note note-${kind}`, text: textContent });
}

export function row(children: (Node | string)[]): HTMLElement {
  return el("div", { class: "row", text: undefined }, children);
}

export function spinner(label: string): HTMLElement {
  return el("div", { class: "status" }, [el("span", { class: "dots" }), label]);
}
