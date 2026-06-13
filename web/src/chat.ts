// Chat-feed UI machinery, reproduced from FileKey's app: typewriter messages with
// the lock-avatar "dp" in the gutter, inline blue links, animated status lines, the
// bottom drop bar, the hamburger menu + appearance toggle. Keeps Drop visually
// identical to the FileKey home.

const $ = (id: string) => document.getElementById(id)!;
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;

// v1 icon paths (verbatim from the app).
export const SVG = {
  logo: `<svg viewBox="0 0 22 27"><path d="M21.9873 8.81596C21.9827 8.75523 21.9678 8.69679 21.9506 8.63607C21.9334 8.57648 21.9174 8.51919 21.8899 8.46419C21.8807 8.44471 21.8796 8.42409 21.8693 8.40461C19.9924 5.27768 17.349 2.63298 14.2221 0.757408C14.2037 0.74595 14.182 0.74595 14.1625 0.735638C14.1086 0.708138 14.0525 0.692095 13.9929 0.674909C13.931 0.657721 13.8715 0.64168 13.8084 0.638242C13.7878 0.638242 13.7706 0.62793 13.75 0.62793H5.5C2.46693 0.62793 0 3.09492 0 6.12793V20.7946C0 23.8277 2.46699 26.2946 5.5 26.2946H16.5C19.5331 26.2946 22 23.8276 22 20.7946V8.87793C22 8.85616 21.9896 8.83773 21.9873 8.81596ZM19.3748 7.96116H18.3332C16.312 7.96116 14.6666 6.31573 14.6666 4.29449V3.25292C16.4793 4.55459 18.073 6.14839 19.3748 7.96116ZM16.4999 24.4612H5.49992C3.47867 24.4612 1.83325 22.8157 1.83325 20.7945V6.12783C1.83325 4.10658 3.47867 2.46116 5.49992 2.46116H12.8332V4.29449C12.8332 7.32756 15.3002 9.79449 18.3332 9.79449H20.1666V20.7945C20.1666 22.8157 18.5212 24.4612 16.4999 24.4612ZM14.6666 14.5462V12.5444C14.6666 10.5232 13.0212 8.87777 10.9999 8.87777C8.97867 8.87777 7.33325 10.5232 7.33325 12.5444V14.5462C6.26877 14.9266 5.49992 15.9338 5.49992 17.1278V19.8778C5.49992 21.3937 6.73397 22.6278 8.24992 22.6278H13.7499C15.2659 22.6278 16.4999 21.3937 16.4999 19.8778V17.1278C16.4999 15.9338 15.7311 14.9266 14.6666 14.5462ZM9.16658 12.5444C9.16658 11.5338 9.98929 10.7111 10.9999 10.7111C12.0105 10.7111 12.8332 11.5338 12.8332 12.5444V14.3778H9.16658V12.5444ZM14.6666 19.8778C14.6666 20.3831 14.2552 20.7944 13.7499 20.7944H8.24992C7.74459 20.7944 7.33325 20.3831 7.33325 19.8778V17.1278C7.33325 16.6224 7.74459 16.2111 8.24992 16.2111H13.7499C14.2552 16.2111 14.6666 16.6224 14.6666 17.1278V19.8778Z"/></svg>`,
  filekey: `<svg viewBox="0 0 13 16"><path d="M10.4867 6.88902V4.77531C10.4867 2.64104 8.7493 0.903607 6.61503 0.903607C4.48076 0.903607 2.74332 2.64104 2.74332 4.77531V6.88902C1.61932 7.29072 0.807471 8.35423 0.807471 9.61495V12.5187C0.807471 14.1194 2.11053 15.4225 3.71125 15.4225H9.51881C11.1195 15.4225 12.4226 14.1194 12.4226 12.5187V9.61495C12.4226 8.35423 11.6107 7.29072 10.4867 6.88902ZM4.67918 4.77531C4.67918 3.70818 5.5479 2.83946 6.61503 2.83946C7.68217 2.83946 8.55088 3.70818 8.55088 4.77531V6.71117H4.67918V4.77531ZM10.4867 12.5187C10.4867 13.0523 10.0524 13.4867 9.51881 13.4867H3.71125C3.17767 13.4867 2.74332 13.0523 2.74332 12.5187V9.61495C2.74332 9.08137 3.17767 8.64702 3.71125 8.64702H9.51881C10.0524 8.64702 10.4867 9.08137 10.4867 9.61495V12.5187Z"/></svg>`,
  file: `<svg viewBox="0 0 25 30"><path d="M24.9856 9.30458C24.9804 9.23557 24.9634 9.16916 24.9439 9.10015C24.9244 9.03245 24.9061 8.96734 24.8749 8.90484C24.8645 8.88271 24.8632 8.85927 24.8515 8.83714C22.7187 5.2838 19.7148 2.27847 16.1615 0.147133C16.1406 0.134112 16.1159 0.134113 16.0938 0.122395C16.0326 0.0911446 15.9688 0.0729129 15.901 0.0533829C15.8307 0.0338515 15.763 0.0156254 15.6914 0.0117188C15.668 0.0117188 15.6484 0 15.625 0H6.25C2.80333 0 0 2.8034 0 6.25V22.9167C0 26.3633 2.8034 29.1667 6.25 29.1667H18.75C22.1967 29.1667 25 26.3633 25 22.9167V9.375C25 9.35026 24.9882 9.32932 24.9856 9.30458ZM22.0168 8.33321H20.8332C18.5364 8.33321 16.6666 6.46342 16.6666 4.16655V2.98295C18.7265 4.46212 20.5375 6.27325 22.0168 8.33321ZM18.7499 27.0832H6.2499C3.95304 27.0832 2.08324 25.2134 2.08324 22.9165V6.24988C2.08324 3.95301 3.95304 2.08321 6.2499 2.08321H14.5832V4.16655C14.5832 7.61322 17.3866 10.4165 20.8332 10.4165H22.9166V22.9165C22.9166 25.2134 21.0468 27.0832 18.7499 27.0832Z"/></svg>`,
  copy: `<svg viewBox="0 0 17 21"><path d="M3.85938 5.22363V3.31738C3.85938 2.47363 4.07292 1.83561 4.5 1.40332C4.92708 0.96582 5.5599 0.74707 6.39844 0.74707H9.33594C9.78906 0.74707 10.1927 0.812174 10.5469 0.942383C10.9062 1.06738 11.2318 1.28092 11.5234 1.58301L15.4141 5.54395C15.7214 5.86165 15.9375 6.2002 16.0625 6.55957C16.1875 6.91374 16.25 7.34863 16.25 7.86426V14.0518C16.25 14.8955 16.0339 15.5335 15.6016 15.9658C15.1745 16.3981 14.5443 16.6143 13.7109 16.6143H12.1094V15.083H13.5703C13.9505 15.083 14.2344 14.9867 14.4219 14.7939C14.6146 14.596 14.7109 14.3174 14.7109 13.958V7.48926H11.2734C10.7891 7.48926 10.4219 7.36686 10.1719 7.12207C9.92188 6.87207 9.79688 6.50488 9.79688 6.02051V2.28613H6.52344C6.14844 2.28613 5.86458 2.38249 5.67188 2.5752C5.48438 2.7679 5.39062 3.04655 5.39062 3.41113V5.22363H3.85938ZM11.0781 5.8252C11.0781 5.96061 11.1068 6.05957 11.1641 6.12207C11.2266 6.17936 11.3229 6.20801 11.4531 6.20801H14.3125L11.0781 2.92676V5.8252ZM-0.0078125 18.0596V7.3252C-0.0078125 6.48145 0.205729 5.84342 0.632812 5.41113C1.0599 4.97363 1.69271 4.75488 2.53125 4.75488H5.25C5.72396 4.75488 6.11458 4.80697 6.42188 4.91113C6.73438 5.01009 7.04688 5.22103 7.35938 5.54395L11.5938 9.84082C11.8125 10.0648 11.9792 10.2783 12.0938 10.4814C12.2083 10.6846 12.2839 10.9111 12.3203 11.1611C12.362 11.4059 12.3828 11.7028 12.3828 12.0518V18.0596C12.3828 18.9033 12.1693 19.5413 11.7422 19.9736C11.3151 20.4059 10.6823 20.6221 9.84375 20.6221H2.53125C1.69271 20.6221 1.0599 20.4059 0.632812 19.9736C0.205729 19.5465 -0.0078125 18.9085 -0.0078125 18.0596ZM1.53125 17.9658C1.53125 18.3304 1.625 18.609 1.8125 18.8018C2 18.9945 2.28125 19.0908 2.65625 19.0908H9.71094C10.0859 19.0908 10.3672 18.9945 10.5547 18.8018C10.7474 18.609 10.8438 18.3304 10.8438 17.9658V12.2314H6.71875C6.16667 12.2314 5.7526 12.096 5.47656 11.8252C5.20052 11.5492 5.0625 11.1299 5.0625 10.5674V6.29395H2.66406C2.28385 6.29395 2 6.3903 1.8125 6.58301C1.625 6.77572 1.53125 7.05176 1.53125 7.41113V17.9658ZM6.875 10.8799H10.6328L6.41406 6.59082V10.4189C6.41406 10.5804 6.45052 10.6976 6.52344 10.7705C6.59635 10.8434 6.71354 10.8799 6.875 10.8799Z"/></svg>`,
  check: `<svg viewBox="0 0 14 14"><path d="M5.28125 13.6611C4.90625 13.6611 4.58594 13.4945 4.32031 13.1611L0.273438 8.09863C0.174479 7.97884 0.101562 7.86165 0.0546875 7.74707C0.0130208 7.63249 -0.0078125 7.5153 -0.0078125 7.39551C-0.0078125 7.12467 0.0807292 6.90072 0.257812 6.72363C0.440104 6.54655 0.669271 6.45801 0.945312 6.45801C1.26302 6.45801 1.53125 6.60124 1.75 6.8877L5.25 11.3799L12.0312 0.606445C12.151 0.424154 12.2734 0.296549 12.3984 0.223633C12.5234 0.145508 12.6849 0.106445 12.8828 0.106445C13.1536 0.106445 13.375 0.192383 13.5469 0.364258C13.7188 0.530924 13.8047 0.749674 13.8047 1.02051C13.8047 1.12988 13.7865 1.24186 13.75 1.35645C13.7135 1.46582 13.6562 1.58301 13.5781 1.70801L6.23438 13.1533C6.00521 13.4919 5.6875 13.6611 5.28125 13.6611Z"/></svg>`,
};

let mainInner: HTMLElement;
let allowAutoScroll = false;

function scrollToBottom() {
  if (!allowAutoScroll) return;
  window.scroll(0, document.body.scrollHeight);
}
const setIcon = (el: Element, cls: string) => el.querySelector("svg")!.setAttribute("class", cls);

export type Seg = string | { t: string; b?: boolean } | { link: string; onClick: () => void };

function typeInto(el: HTMLElement, text: string, perFrame: number): Promise<void> {
  if (REDUCED) {
    el.textContent = text;
    scrollToBottom();
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    let i = 0;
    const frame = () => {
      i += perFrame;
      el.textContent = text.slice(0, i);
      scrollToBottom();
      i < text.length ? requestAnimationFrame(frame) : resolve();
    };
    requestAnimationFrame(frame);
  });
}

function shell(dp = "std_dp", icon = "filekey_icon"): HTMLElement {
  const outer = document.createElement("div");
  outer.className = "std_outer";
  outer.innerHTML = `<div class="std_msg_inner"><span class="${dp}">${SVG.filekey}</span><span class="std_msg"></span></div>`;
  setIcon(outer.querySelector(`.${dp}`)!, icon);
  mainInner.appendChild(outer);
  return outer.querySelector(".std_msg") as HTMLElement;
}

export interface MsgOpts {
  speed?: number;
  dp?: string;
  icon?: string;
}

export async function appMsg(segs: Seg[], opts: MsgOpts = {}): Promise<HTMLElement> {
  const speed = opts.speed ?? 8;
  const msg = shell(opts.dp ?? "std_dp", opts.icon ?? "filekey_icon");
  scrollToBottom();
  for (const seg of segs) {
    if (typeof seg === "string") {
      const s = document.createElement("span");
      msg.appendChild(s);
      await typeInto(s, seg, speed);
    } else if ("t" in seg) {
      const s = document.createElement(seg.b ? "strong" : "span");
      msg.appendChild(s);
      await typeInto(s, seg.t, speed);
    } else {
      const a = document.createElement("span");
      a.className = "msg_clickable no_select";
      a.textContent = seg.link;
      a.addEventListener("click", seg.onClick);
      msg.appendChild(a);
      if (!REDUCED) await new Promise((r) => setTimeout(r, 40));
    }
  }
  scrollToBottom();
  return msg;
}

export interface Status {
  done(text?: string): void;
  remove(): void;
}

export function statusMsg(label: string): Status {
  const outer = document.createElement("div");
  outer.className = "std_status_outer";
  outer.innerHTML = `<div class="std_status_inner"><span class="std_dp">${SVG.filekey}</span><span class="std_status"></span></div>`;
  setIcon(outer.querySelector(".std_dp")!, "filekey_icon");
  mainInner.appendChild(outer);
  const el = outer.querySelector(".std_status") as HTMLElement;
  let active = true;
  const start = performance.now();
  const tick = () => {
    if (!active) return;
    const s = Math.round((performance.now() - start) / 1000) % 3;
    el.textContent = label + (s === 0 ? "." : s === 1 ? ".." : "...");
    requestAnimationFrame(tick);
  };
  tick();
  scrollToBottom();
  return {
    done(text?: string) {
      active = false;
      if (text) el.textContent = text;
    },
    remove() {
      active = false;
      outer.remove();
    },
  };
}

/** A right-aligned mono box revealing the receiver's Drop link, with a Copy action. */
export function linkReveal(url: string): void {
  const cont = document.createElement("div");
  cont.className = "pub_key_textarea_cont set_right";
  const box = document.createElement("div");
  box.className = "pub_key_textarea";
  box.style.userSelect = "all";
  box.textContent = url;
  const actions = document.createElement("div");
  actions.className = "pub_key_actions";
  const copy = document.createElement("span");
  copy.className = "copy_button no_select";
  copy.innerHTML = `${SVG.copy.replace("<svg", '<svg class="copy_icon"')}Copy`;
  copy.addEventListener("click", () => {
    void navigator.clipboard?.writeText(url);
    copy.innerHTML = `${SVG.check.replace("<svg", '<svg class="copy_icon"')}Copied`;
  });
  actions.appendChild(copy);
  cont.append(box, actions);
  mainInner.appendChild(cont);
  scrollToBottom();
}

/** A right-aligned input prompt (email, label) with a Confirm action. */
export function inputPrompt(fields: { key: string; placeholder: string; type?: string }[]): Promise<Record<string, string>> {
  return new Promise((resolve) => {
    const cont = document.createElement("div");
    cont.className = "pub_key_textarea_cont set_right";
    const inputs: Record<string, HTMLInputElement> = {};
    for (const f of fields) {
      const i = document.createElement("input");
      i.className = "fk_input";
      i.type = f.type ?? "text";
      i.placeholder = f.placeholder;
      inputs[f.key] = i;
      cont.appendChild(i);
    }
    const actions = document.createElement("div");
    actions.className = "pub_key_actions";
    const confirm = document.createElement("span");
    confirm.className = "confirm_pub_key no_select";
    confirm.innerHTML = `${SVG.check.replace("<svg", '<svg class="confirm_icon"')}Confirm`;
    const submit = () => {
      const out: Record<string, string> = {};
      for (const f of fields) out[f.key] = inputs[f.key]!.value.trim();
      resolve(out);
    };
    confirm.addEventListener("click", submit);
    actions.appendChild(confirm);
    cont.appendChild(actions);
    mainInner.appendChild(cont);
    const first = fields[0] && inputs[fields[0].key];
    first?.focus();
    first?.addEventListener("keydown", (e) => {
      if ((e as KeyboardEvent).key === "Enter") submit();
    });
    scrollToBottom();
  });
}

// ---- drop bar ----
export function showDropBar(text: string, onFile: (f: File) => void): void {
  const bar = $("drop_container");
  (bar.querySelector(".file_title") as HTMLElement).textContent = text;
  (bar.querySelector(".dc_icon_container") as HTMLElement).innerHTML =
    `<div class="icon_container some_background">${SVG.file.replace("<svg", '<svg class="file_icon"')}</div>`;
  bar.style.display = "flex";
  const input = $("file_input") as HTMLInputElement;
  ($("choose_file") as HTMLButtonElement).onclick = () => input.click();
  input.onchange = () => {
    const f = input.files?.[0];
    if (f) onFile(f);
  };
  const stop = (e: Event) => {
    e.preventDefault();
    e.stopPropagation();
  };
  bar.addEventListener("dragover", stop);
  bar.addEventListener("drop", (e) => {
    stop(e);
    const f = (e as DragEvent).dataTransfer?.files?.[0];
    if (f) onFile(f);
  });
}

export function hideDropBar(): void {
  $("drop_container").style.display = "none";
}

// ---- chrome: logo, menu, theme ----
function effectiveDark(mode: string): boolean {
  return mode === "dark" || (mode === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
}

function setTheme(mode: string): void {
  try {
    localStorage.setItem("filekey-theme", mode);
  } catch {
    /* private mode */
  }
  const dark = effectiveDark(mode);
  if (dark) document.documentElement.dataset.theme = "dark";
  else delete document.documentElement.dataset.theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", dark ? "#0c0c0e" : "#ffffff");
  document.querySelectorAll(".theme_opt").forEach((o) => o.classList.toggle("active", (o as HTMLElement).dataset.mode === mode));
}

export function initChrome(): void {
  mainInner = $("main_inner");
  allowAutoScroll = true;

  $("logo_bar").innerHTML =
    `${SVG.logo.replace("<svg", '<svg class="filekey_logo_icon"')}<span id="logo_txt">FileKey</span><span class="badge">Drop</span>`;
  $("logo_bar").addEventListener("click", () => (location.href = "/"));

  const icon = $("chiz_icon_container");
  const menu = $("chiz_menu_container");
  const hidden = $("chiz_hidden_click_container");
  const close = () => {
    icon.classList.remove("is-open");
    menu.style.display = "none";
    hidden.style.display = "none";
  };
  icon.addEventListener("click", () => {
    if (icon.classList.contains("is-open")) return close();
    icon.classList.add("is-open");
    menu.style.display = "block";
    hidden.style.display = "block";
  });
  hidden.addEventListener("click", close);

  let stored = "light";
  try {
    stored = localStorage.getItem("filekey-theme") || "light";
  } catch {
    /* private mode */
  }
  setTheme(stored);
  $("theme_row").addEventListener("click", (e) => {
    const opt = (e.target as HTMLElement).closest(".theme_opt") as HTMLElement | null;
    if (opt?.dataset.mode) setTheme(opt.dataset.mode);
  });
}
