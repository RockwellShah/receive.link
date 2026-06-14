// FileKey UI machinery — VENDORED VERBATIM from FileKey web/app.ts (read-only; see
// README). The chat feed, typewriter, StatusMsg, cards, saveBlob, marching-ants
// drop bar, hamburger menu + Light/Dark/Auto toggle. Do NOT edit here; re-vendor
// from FileKey. Only deltas vs app.ts: parameterized (no Vault globals), Save-only
// card, and a couple of generic prompt/reveal helpers built from the same parts.

import { collectFromInput, collectFromDrop, type BundleItem } from "./bundle";

// ---- v1 icons (verbatim SVG paths from app.ts) ----
export const SVG = {
  logo: `<svg viewBox="0 0 22 27"><path d="M21.9873 8.81596C21.9827 8.75523 21.9678 8.69679 21.9506 8.63607C21.9334 8.57648 21.9174 8.51919 21.8899 8.46419C21.8807 8.44471 21.8796 8.42409 21.8693 8.40461C19.9924 5.27768 17.349 2.63298 14.2221 0.757408C14.2037 0.74595 14.182 0.74595 14.1625 0.735638C14.1086 0.708138 14.0525 0.692095 13.9929 0.674909C13.931 0.657721 13.8715 0.64168 13.8084 0.638242C13.7878 0.638242 13.7706 0.62793 13.75 0.62793H5.5C2.46693 0.62793 0 3.09492 0 6.12793V20.7946C0 23.8277 2.46699 26.2946 5.5 26.2946H16.5C19.5331 26.2946 22 23.8276 22 20.7946V8.87793C22 8.85616 21.9896 8.83773 21.9873 8.81596ZM19.3748 7.96116H18.3332C16.312 7.96116 14.6666 6.31573 14.6666 4.29449V3.25292C16.4793 4.55459 18.073 6.14839 19.3748 7.96116ZM16.4999 24.4612H5.49992C3.47867 24.4612 1.83325 22.8157 1.83325 20.7945V6.12783C1.83325 4.10658 3.47867 2.46116 5.49992 2.46116H12.8332V4.29449C12.8332 7.32756 15.3002 9.79449 18.3332 9.79449H20.1666V20.7945C20.1666 22.8157 18.5212 24.4612 16.4999 24.4612ZM14.6666 14.5462V12.5444C14.6666 10.5232 13.0212 8.87777 10.9999 8.87777C8.97867 8.87777 7.33325 10.5232 7.33325 12.5444V14.5462C6.26877 14.9266 5.49992 15.9338 5.49992 17.1278V19.8778C5.49992 21.3937 6.73397 22.6278 8.24992 22.6278H13.7499C15.2659 22.6278 16.4999 21.3937 16.4999 19.8778V17.1278C16.4999 15.9338 15.7311 14.9266 14.6666 14.5462ZM9.16658 12.5444C9.16658 11.5338 9.98929 10.7111 10.9999 10.7111C12.0105 10.7111 12.8332 11.5338 12.8332 12.5444V14.3778H9.16658V12.5444ZM14.6666 19.8778C14.6666 20.3831 14.2552 20.7944 13.7499 20.7944H8.24992C7.74459 20.7944 7.33325 20.3831 7.33325 19.8778V17.1278C7.33325 16.6224 7.74459 16.2111 8.24992 16.2111H13.7499C14.2552 16.2111 14.6666 16.6224 14.6666 17.1278V19.8778Z"/></svg>`,
  filekey: `<svg viewBox="0 0 13 16"><path d="M10.4867 6.88902V4.77531C10.4867 2.64104 8.7493 0.903607 6.61503 0.903607C4.48076 0.903607 2.74332 2.64104 2.74332 4.77531V6.88902C1.61932 7.29072 0.807471 8.35423 0.807471 9.61495V12.5187C0.807471 14.1194 2.11053 15.4225 3.71125 15.4225H9.51881C11.1195 15.4225 12.4226 14.1194 12.4226 12.5187V9.61495C12.4226 8.35423 11.6107 7.29072 10.4867 6.88902ZM4.67918 4.77531C4.67918 3.70818 5.5479 2.83946 6.61503 2.83946C7.68217 2.83946 8.55088 3.70818 8.55088 4.77531V6.71117H4.67918V4.77531ZM10.4867 12.5187C10.4867 13.0523 10.0524 13.4867 9.51881 13.4867H3.71125C3.17767 13.4867 2.74332 13.0523 2.74332 12.5187V9.61495C2.74332 9.08137 3.17767 8.64702 3.71125 8.64702H9.51881C10.0524 8.64702 10.4867 9.08137 10.4867 9.61495V12.5187Z"/></svg>`,
  file: `<svg viewBox="0 0 25 30"><path d="M24.9856 9.30458C24.9804 9.23557 24.9634 9.16916 24.9439 9.10015C24.9244 9.03245 24.9061 8.96734 24.8749 8.90484C24.8645 8.88271 24.8632 8.85927 24.8515 8.83714C22.7187 5.2838 19.7148 2.27847 16.1615 0.147133C16.1406 0.134112 16.1159 0.134113 16.0938 0.122395C16.0326 0.0911446 15.9688 0.0729129 15.901 0.0533829C15.8307 0.0338515 15.763 0.0156254 15.6914 0.0117188C15.668 0.0117188 15.6484 0 15.625 0H6.25C2.80333 0 0 2.8034 0 6.25V22.9167C0 26.3633 2.8034 29.1667 6.25 29.1667H18.75C22.1967 29.1667 25 26.3633 25 22.9167V9.375C25 9.35026 24.9882 9.32932 24.9856 9.30458ZM22.0168 8.33321H20.8332C18.5364 8.33321 16.6666 6.46342 16.6666 4.16655V2.98295C18.7265 4.46212 20.5375 6.27325 22.0168 8.33321ZM18.7499 27.0832H6.2499C3.95304 27.0832 2.08324 25.2134 2.08324 22.9165V6.24988C2.08324 3.95301 3.95304 2.08321 6.2499 2.08321H14.5832V4.16655C14.5832 7.61322 17.3866 10.4165 20.8332 10.4165H22.9166V22.9165C22.9166 25.2134 21.0468 27.0832 18.7499 27.0832Z"/><path d="M17.5457 16.1931C17.4066 16.0458 17.2306 15.9722 17.0178 15.9722H7.69971C7.47873 15.9722 7.29457 16.0458 7.14725 16.1931C6.99993 16.3323 6.92627 16.5083 6.92627 16.7211C6.92627 16.9339 6.99993 17.1139 7.14725 17.2612C7.29457 17.4086 7.47873 17.4822 7.69971 17.4822H17.0178C17.2306 17.4822 17.4066 17.4086 17.5457 17.2612C17.693 17.1139 17.7667 16.9339 17.7667 16.7211C17.7667 16.5083 17.693 16.3323 17.5457 16.1931Z"/><path d="M17.5457 20.4777C17.4066 20.3304 17.2306 20.2568 17.0178 20.2568H7.69971C7.47873 20.2568 7.29457 20.3304 7.14725 20.4777C6.99993 20.6251 6.92627 20.8092 6.92627 21.0302C6.92627 21.2348 6.99993 21.4108 7.14725 21.5581C7.29457 21.6972 7.47873 21.7668 7.69971 21.7668H17.0178C17.2306 21.7668 17.4066 21.6972 17.5457 21.5581C17.693 21.4108 17.7667 21.2348 17.7667 21.0302C17.7667 20.8092 17.693 20.6251 17.5457 20.4777Z"/></svg>`,
  copy: `<svg viewBox="0 0 17 21"><path d="M3.85938 5.22363V3.31738C3.85938 2.47363 4.07292 1.83561 4.5 1.40332C4.92708 0.96582 5.5599 0.74707 6.39844 0.74707H9.33594C9.78906 0.74707 10.1927 0.812174 10.5469 0.942383C10.9062 1.06738 11.2318 1.28092 11.5234 1.58301L15.4141 5.54395C15.7214 5.86165 15.9375 6.2002 16.0625 6.55957C16.1875 6.91374 16.25 7.34863 16.25 7.86426V14.0518C16.25 14.8955 16.0339 15.5335 15.6016 15.9658C15.1745 16.3981 14.5443 16.6143 13.7109 16.6143H12.1094V15.083H13.5703C13.9505 15.083 14.2344 14.9867 14.4219 14.7939C14.6146 14.596 14.7109 14.3174 14.7109 13.958V7.48926H11.2734C10.7891 7.48926 10.4219 7.36686 10.1719 7.12207C9.92188 6.87207 9.79688 6.50488 9.79688 6.02051V2.28613H6.52344C6.14844 2.28613 5.86458 2.38249 5.67188 2.5752C5.48438 2.7679 5.39062 3.04655 5.39062 3.41113V5.22363H3.85938ZM11.0781 5.8252C11.0781 5.96061 11.1068 6.05957 11.1641 6.12207C11.2266 6.17936 11.3229 6.20801 11.4531 6.20801H14.3125L11.0781 2.92676V5.8252ZM-0.0078125 18.0596V7.3252C-0.0078125 6.48145 0.205729 5.84342 0.632812 5.41113C1.0599 4.97363 1.69271 4.75488 2.53125 4.75488H5.25C5.72396 4.75488 6.11458 4.80697 6.42188 4.91113C6.73438 5.01009 7.04688 5.22103 7.35938 5.54395L11.5938 9.84082C11.8125 10.0648 11.9792 10.2783 12.0938 10.4814C12.2083 10.6846 12.2839 10.9111 12.3203 11.1611C12.362 11.4059 12.3828 11.7028 12.3828 12.0518V18.0596C12.3828 18.9033 12.1693 19.5413 11.7422 19.9736C11.3151 20.4059 10.6823 20.6221 9.84375 20.6221H2.53125C1.69271 20.6221 1.0599 20.4059 0.632812 19.9736C0.205729 19.5465 -0.0078125 18.9085 -0.0078125 18.0596ZM1.53125 17.9658C1.53125 18.3304 1.625 18.609 1.8125 18.8018C2 18.9945 2.28125 19.0908 2.65625 19.0908H9.71094C10.0859 19.0908 10.3672 18.9945 10.5547 18.8018C10.7474 18.609 10.8438 18.3304 10.8438 17.9658V12.2314H6.71875C6.16667 12.2314 5.7526 12.096 5.47656 11.8252C5.20052 11.5492 5.0625 11.1299 5.0625 10.5674V6.29395H2.66406C2.28385 6.29395 2 6.3903 1.8125 6.58301C1.625 6.77572 1.53125 7.05176 1.53125 7.41113V17.9658ZM6.875 10.8799H10.6328L6.41406 6.59082V10.4189C6.41406 10.5804 6.45052 10.6976 6.52344 10.7705C6.59635 10.8434 6.71354 10.8799 6.875 10.8799Z"/></svg>`,
  save: `<svg viewBox="0 0 12 15"><path d="M5.98438 0.692383C6.23438 0.692383 6.4375 0.773112 6.59375 0.93457C6.75521 1.09603 6.83594 1.30436 6.83594 1.55957V8.8252L6.76562 10.4658L8.84375 8.17676L10.4531 6.59863C10.526 6.52051 10.6146 6.45801 10.7188 6.41113C10.8281 6.36426 10.9427 6.34082 11.0625 6.34082C11.3021 6.34082 11.5 6.42155 11.6562 6.58301C11.8125 6.74447 11.8906 6.94759 11.8906 7.19238C11.8906 7.30176 11.8672 7.40853 11.8203 7.5127C11.7734 7.61686 11.7031 7.71582 11.6094 7.80957L6.61719 12.7471C6.53385 12.8356 6.4375 12.9059 6.32812 12.958C6.21875 13.0101 6.10417 13.0361 5.98438 13.0361C5.85938 13.0361 5.74219 13.0101 5.63281 12.958C5.52344 12.9059 5.42708 12.8356 5.34375 12.7471L0.351562 7.80957C0.263021 7.71582 0.195312 7.61686 0.148438 7.5127C0.101562 7.40853 0.078125 7.30176 0.078125 7.19238C0.078125 6.94759 0.15625 6.74447 0.3125 6.58301C0.46875 6.42155 0.666667 6.34082 0.90625 6.34082C1.02604 6.34082 1.13802 6.36426 1.24219 6.41113C1.34635 6.45801 1.4375 6.52051 1.51562 6.59863L3.11719 8.17676L5.20312 10.4736L5.125 8.8252V1.55957C5.125 1.30436 5.20312 1.09603 5.35938 0.93457C5.52083 0.773112 5.72917 0.692383 5.98438 0.692383ZM0.8125 13.0127H11.1328C11.3776 13.0127 11.5781 13.0934 11.7344 13.2549C11.8906 13.4163 11.9688 13.6169 11.9688 13.8564C11.9688 14.096 11.8906 14.2965 11.7344 14.458C11.5781 14.6195 11.3776 14.7002 11.1328 14.7002H0.8125C0.578125 14.7002 0.382812 14.6195 0.226562 14.458C0.0703125 14.2965 -0.0078125 14.096 -0.0078125 13.8564C-0.0078125 13.6169 0.0703125 13.4163 0.226562 13.2549C0.382812 13.0934 0.578125 13.0127 0.8125 13.0127Z"/></svg>`,
  check: `<svg viewBox="0 0 14 14"><path d="M5.28125 13.6611C4.90625 13.6611 4.58594 13.4945 4.32031 13.1611L0.273438 8.09863C0.174479 7.97884 0.101562 7.86165 0.0546875 7.74707C0.0130208 7.63249 -0.0078125 7.5153 -0.0078125 7.39551C-0.0078125 7.12467 0.0807292 6.90072 0.257812 6.72363C0.440104 6.54655 0.669271 6.45801 0.945312 6.45801C1.26302 6.45801 1.53125 6.60124 1.75 6.8877L5.25 11.3799L12.0312 0.606445C12.151 0.424154 12.2734 0.296549 12.3984 0.223633C12.5234 0.145508 12.6849 0.106445 12.8828 0.106445C13.1536 0.106445 13.375 0.192383 13.5469 0.364258C13.7188 0.530924 13.8047 0.749674 13.8047 1.02051C13.8047 1.12988 13.7865 1.24186 13.75 1.35645C13.7135 1.46582 13.6562 1.58301 13.5781 1.70801L6.23438 13.1533C6.00521 13.4919 5.6875 13.6611 5.28125 13.6611Z"/></svg>`,
  outbound: `<svg viewBox="0 0 24 24" class="outbound_link"><path d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25"/></svg>`,
  plus: `<svg viewBox="0 0 34 33"><path d="M17 32.7086C14.7774 32.7086 12.6917 32.2873 10.7429 31.4446C8.79413 30.6124 7.08238 29.4589 5.60764 27.9842C4.1329 26.5095 2.97417 24.7977 2.13146 22.8489C1.29929 20.9002 0.883203 18.8145 0.883203 16.5918C0.883203 14.3692 1.29929 12.2835 2.13146 10.3347C2.97417 8.38596 4.1329 6.67421 5.60764 5.19947C7.08238 3.7142 8.79413 2.55547 10.7429 1.7233C12.6917 0.891126 14.7774 0.475039 17 0.475039C19.2226 0.475039 21.3083 0.891126 23.2571 1.7233C25.2059 2.55547 26.9176 3.7142 28.3924 5.19947C29.8671 6.67421 31.0206 8.38596 31.8527 10.3347C32.6954 12.2835 33.1168 14.3692 33.1168 16.5918C33.1168 18.8145 32.6954 20.9002 31.8527 22.8489C31.0206 24.7977 29.8671 26.5095 28.3924 27.9842C26.9176 29.4589 25.2059 30.6124 23.2571 31.4446C21.3083 32.2873 19.2226 32.7086 17 32.7086ZM17 30.0225C18.854 30.0225 20.592 29.6749 22.2143 28.9796C23.8365 28.2844 25.2638 27.3206 26.4963 26.0881C27.7287 24.8556 28.6926 23.4283 29.3878 21.8061C30.083 20.1839 30.4307 18.4458 30.4307 16.5918C30.4307 14.7379 30.083 12.9998 29.3878 11.3776C28.6926 9.74483 27.7287 8.31749 26.4963 7.09557C25.2638 5.86311 23.8365 4.89926 22.2143 4.20402C20.592 3.50879 18.854 3.16117 17 3.16117C15.146 3.16117 13.408 3.50879 11.7857 4.20402C10.1635 4.89926 8.73619 5.86311 7.50373 7.09557C6.27127 8.31749 5.30742 9.74483 4.61219 11.3776C3.91695 12.9998 3.56934 14.7379 3.56934 16.5918C3.56934 18.4458 3.91695 20.1839 4.61219 21.8061C5.30742 23.4283 6.27127 24.8556 7.50373 26.0881C8.73619 27.3206 10.1635 28.2844 11.7857 28.9796C13.408 29.6749 15.146 30.0225 17 30.0225ZM9.66844 16.5918C9.66844 16.1915 9.78958 15.8703 10.0319 15.628C10.2847 15.3752 10.6165 15.2488 11.0273 15.2488H15.6727V10.6033C15.6727 10.2031 15.7939 9.8765 16.0362 9.62369C16.2784 9.37088 16.5892 9.24447 16.9684 9.24447C17.3687 9.24447 17.69 9.37088 17.9322 9.62369C18.1851 9.86597 18.3115 10.1925 18.3115 10.6033V15.2488H22.9727C23.373 15.2488 23.6943 15.3752 23.9365 15.628C24.1894 15.8703 24.3158 16.1915 24.3158 16.5918C24.3158 16.9711 24.1894 17.2818 23.9365 17.5241C23.6943 17.7664 23.373 17.8875 22.9727 17.8875H18.3115V22.5487C18.3115 22.949 18.1851 23.2756 17.9322 23.5284C17.69 23.7707 17.3687 23.8918 16.9684 23.8918C16.5892 23.8918 16.2784 23.7707 16.0362 23.5284C15.7939 23.2756 15.6727 22.949 15.6727 22.5487V17.8875H11.0273C10.627 17.8875 10.3005 17.7664 10.0477 17.5241C9.79484 17.2818 9.66844 16.9711 9.66844 16.5918Z"/></svg>`,
};

const EXT_ICON = SVG.outbound.replace("outbound_link", "ext_icon");
export const extLink = (href: string, text: string) =>
  `<a class="borderless msg_link" href="${href}" target="_blank" rel="noopener noreferrer">${text}${EXT_ICON}</a>`;
export const extLinkDot = (href: string, text: string) => `<span class="nobreak">${extLink(href, text)}.</span>`;

const $ = (id: string) => document.getElementById(id)!;
export const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const stripBidi = (s: string) => s.replace(/[‪-‮⁦-⁩]/g, "");
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
export const ERR = { speed: 4, dp: "failed_dp", icon: "failed_filekey_icon" };
export const OK = { dp: "ok_dp", icon: "ok_filekey_icon" };

let mainInner: HTMLElement;
let allowAutoScroll = false;
let statusCount = 0;
let dragWired = false;
let dropOnItems: ((items: BundleItem[]) => void) | null = null;

function scrollToBottom() {
  if (!allowAutoScroll) return;
  const three_quarters = document.body.clientHeight * 0.75;
  if (mainInner.clientHeight >= three_quarters) window.scroll(0, document.body.scrollHeight + document.body.scrollHeight / 10);
}
const setIcon = (el: Element, cls: string) => el.querySelector("svg")!.setAttribute("class", cls);
function fmtBytes(n: number): string {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${Math.round(n / 1024 ** 2)} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} KB`;
  return `${n} B`;
}
const STREAM_THRESHOLD = 64 * 1024 * 1024;

// ---- typewriter (v1 std_fillTextBoxAnimation) ----
export type Seg = string | { t: string; b?: boolean } | { link: string; onClick: () => void } | { html: string };
function typeInto(el: HTMLElement, text: string, perFrame: number): Promise<void> {
  if (REDUCED) { el.textContent = text; scrollToBottom(); return Promise.resolve(); }
  return new Promise((resolve) => {
    let i = 0;
    const frame = () => { i += perFrame; el.textContent = text.slice(0, i); scrollToBottom(); i < text.length ? requestAnimationFrame(frame) : resolve(); };
    requestAnimationFrame(frame);
  });
}
function typeHtmlInto(dest: HTMLElement, html: string, perFrame: number): Promise<void> {
  const src = document.createElement("div");
  src.innerHTML = html;
  if (REDUCED) { dest.innerHTML = html; scrollToBottom(); return Promise.resolve(); }
  const typeText = (tn: Text, text: string) => new Promise<void>((resolve) => {
    let i = 0;
    const frame = () => { i += perFrame; tn.data = text.slice(0, i); scrollToBottom(); i < text.length ? requestAnimationFrame(frame) : resolve(); };
    requestAnimationFrame(frame);
  });
  const walk = async (from: Node, to: Node): Promise<void> => {
    for (const child of Array.from(from.childNodes)) {
      if (child.nodeType === Node.TEXT_NODE) { const tn = document.createTextNode(""); to.appendChild(tn); await typeText(tn, (child as Text).data); }
      else if (child.nodeType === Node.ELEMENT_NODE) { const clone = (child as Element).cloneNode(false); to.appendChild(clone); await walk(child, clone); }
    }
  };
  return walk(src, dest);
}
function appShell(dp = "std_dp", icon = "filekey_icon"): HTMLElement {
  const outer = document.createElement("div");
  outer.className = "std_outer";
  outer.innerHTML = `<div class="std_msg_inner"><span class="${dp}">${SVG.filekey}</span><span class="std_msg"></span></div>`;
  setIcon(outer.querySelector(`.${dp}`)!, icon);
  mainInner.appendChild(outer);
  return outer.querySelector(".std_msg") as HTMLElement;
}
export async function appMsg(segs: Seg[], opts: { speed?: number; dp?: string; icon?: string } = {}): Promise<HTMLElement> {
  const speed = opts.speed ?? 8;
  const msg = appShell(opts.dp ?? "std_dp", opts.icon ?? "filekey_icon");
  scrollToBottom();
  for (const seg of segs) {
    if (typeof seg === "string") { const s = document.createElement("span"); msg.appendChild(s); await typeInto(s, seg, speed); }
    else if ("t" in seg) { const s = document.createElement(seg.b ? "strong" : "span"); msg.appendChild(s); await typeInto(s, seg.t, speed); }
    else if ("link" in seg) { const a = document.createElement("span"); a.className = "msg_clickable no_select"; a.textContent = seg.link; a.addEventListener("click", seg.onClick); msg.appendChild(a); if (!REDUCED) await new Promise((r) => setTimeout(r, 40)); }
    else { const s = document.createElement("span"); msg.appendChild(s); await typeHtmlInto(s, seg.html, speed); }
  }
  scrollToBottom();
  return msg;
}
export function actionRow(host: HTMLElement, actions: { label: string; muted?: boolean; onClick: () => void }[]): void {
  const row = document.createElement("div");
  row.className = "msg_actions";
  for (const a of actions) {
    const s = document.createElement("span");
    s.className = `${a.muted ? "cancel_pub_key" : "confirm_pub_key"} no_select`;
    s.textContent = a.label;
    s.addEventListener("click", a.onClick);
    row.appendChild(s);
  }
  host.appendChild(row);
  scrollToBottom();
}

// ---- animated status (v1 set3dotStatusAnimation) ----
export class StatusMsg {
  msg: string; el: HTMLElement; cancelEl: HTMLElement; outer: HTMLElement; active = true; cancelled = false; start = performance.now();
  constructor(label: boolean | string) {
    this.msg = typeof label === "string" ? label : label ? "Encrypting" : "Decrypting";
    this.outer = document.createElement("div");
    this.outer.className = "std_status_outer";
    this.outer.innerHTML = `<div class="std_status_inner"><span class="std_dp">${SVG.filekey}</span><span class="std_status" id="status_${statusCount++}"></span><span class="std_status_cancel no_select" style="display:none;margin-left:6px"><span style="color:var(--fk-faint)">·</span><span class="fk_cancel_act" style="color:var(--fk-link);font-weight:500;cursor:pointer;margin-left:6px">Cancel</span></span></div>`;
    setIcon(this.outer.querySelector(".std_dp")!, "filekey_icon");
    mainInner.appendChild(this.outer);
    this.el = this.outer.querySelector(".std_status") as HTMLElement;
    this.cancelEl = this.outer.querySelector(".std_status_cancel") as HTMLElement;
    scrollToBottom();
    const tick = () => { if (!this.active) return; const s = Math.round((performance.now() - this.start) / 1000) % 3; this.el.textContent = this.msg + (s === 0 ? "." : s === 1 ? ".." : "..."); requestAnimationFrame(tick); };
    tick();
  }
  enableCancel(onCancel?: () => void) {
    this.cancelEl.style.display = "";
    (this.cancelEl.querySelector(".fk_cancel_act") as HTMLElement).addEventListener("click", () => { this.cancel(); onCancel?.(); });
  }
  cancel() {
    if (this.cancelled) return;
    this.cancelled = true; this.active = false;
    this.el.textContent = `${this.msg}… Cancelled`;
    this.cancelEl.style.display = "none";
  }
  progress(done: number, total: number) {
    if (this.cancelled) return;
    this.active = false;
    this.el.textContent = `${this.msg}… ${fmtBytes(done)} of ${fmtBytes(total)}`;
  }
  finish(label: string) { this.active = false; this.el.textContent = label; this.cancelEl.style.display = "none"; }
  done() { this.finish(this.msg + "... Done!"); }
  fail() { this.active = false; this.outer.remove(); }
}

// ---- file cards (v1 html_newFileUpload / html_newDownload) ----
function fnameHtml(filename: string): string {
  filename = stripBidi(filename);
  const safe = esc(filename);
  if (filename.length <= 16) return `<span class="file_title" title="${safe}">${safe}</span>`;
  const tailLen = Math.min(12, Math.ceil(filename.length * 0.35));
  const head = esc(filename.slice(0, filename.length - tailLen));
  const tail = esc(filename.slice(filename.length - tailLen));
  return `<span class="file_title fname" title="${safe}"><span class="fname_head">${head}</span><span class="fname_tail">${tail}</span></span>`;
}
export function uploadCard(filename: string, typeLabel: string): void {
  const outer = document.createElement("div");
  outer.className = "std_upload_outer";
  outer.innerHTML = `<div class="std_uploaded set_right"><div class="icon_container">${SVG.file}</div><div class="std_file_container">${fnameHtml(filename)}<span class="file_status">${esc(typeLabel)}</span></div></div>`;
  setIcon(outer.querySelector(".icon_container")!, "file_icon");
  mainInner.appendChild(outer);
  scrollToBottom();
}
/** Download card (Drop is Save-only; no re-share). */
export function saveCard(filename: string, typeLabel: string, dataBlob: Blob): void {
  const outer = document.createElement("div");
  outer.className = "std_dl_outer";
  outer.innerHTML = `<div class="std_download"><div class="std_inner_flex"><div class="icon_container some_background">${SVG.file}</div><div class="std_file_container">${fnameHtml(filename)}<span class="file_status">${esc(typeLabel)}</span><div class="download_icon_container"><span class="dl_action save_act">${SVG.save} Save</span></div></div></div></div>`;
  setIcon(outer.querySelector(".icon_container")!, "file_icon");
  setIcon(outer.querySelector(".save_act")!, "save_icon");
  (outer.querySelector(".save_act") as HTMLElement).addEventListener("click", () => void saveBlob(dataBlob, filename));
  mainInner.appendChild(outer);
  scrollToBottom();
}
function sanitizeName(name: string) { return (stripBidi(name).replace(/[\/\\]/g, "_").replace(/[\x00-\x1f]/g, "").trim() || "filekey-output").slice(0, 200); }
async function saveBlob(blob: Blob, filename: string) {
  const name = sanitizeName(filename);
  const big = blob.size >= STREAM_THRESHOLD;
  const w = window as unknown as { showSaveFilePicker?: (o: unknown) => Promise<{ createWritable: () => Promise<{ write: (b: Blob) => Promise<void>; close: () => Promise<void> }> }> };
  if (w.showSaveFilePicker) {
    let st: StatusMsg | null = null;
    try {
      const h = await w.showSaveFilePicker({ suggestedName: name });
      const ws = await h.createWritable();
      st = new StatusMsg("Saving");
      await ws.write(blob); await ws.close();
      st.finish("Saved ✓");
      return;
    } catch (e) {
      st?.fail();
      if ((e as Error).name === "AbortError") return;
    }
  }
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; a.click();
  void appMsg([big ? "Your download is in progress. Keep this tab open until it finishes." : "Saved to your downloads."], { speed: 6 });
  const ttl = Math.min(600_000, Math.max(60_000, Math.ceil(blob.size / (1024 * 1024)) * 1000));
  setTimeout(() => URL.revokeObjectURL(a.href), ttl);
}

// ---- marching-ants dashed border on the drop zone (v1 createAnimatedBorder) ----
function marchingBorder(el: HTMLElement) {
  const NS_SVG = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS_SVG, "svg");
  Object.assign(svg.style, { position: "absolute", inset: "0", width: "100%", height: "100%", pointerEvents: "none", overflow: "visible" } as CSSStyleDeclaration);
  const rect = document.createElementNS(NS_SVG, "rect");
  rect.setAttribute("x", "1"); rect.setAttribute("y", "1"); rect.setAttribute("rx", "14"); rect.setAttribute("fill", "none");
  rect.setAttribute("stroke", "#1377f980"); rect.setAttribute("stroke-width", "2"); rect.setAttribute("stroke-dasharray", "3 6"); rect.setAttribute("stroke-linecap", "round");
  svg.appendChild(rect); el.prepend(svg);
  const size = () => { const w = el.clientWidth - 2, h = el.clientHeight - 2; if (w > 0 && h > 0) { rect.setAttribute("width", String(w)); rect.setAttribute("height", String(h)); } };
  new ResizeObserver(size).observe(el); size();
  if (!REDUCED) { let off = 0; const step = () => { off = (off - 0.25) % 9; rect.setAttribute("stroke-dashoffset", String(off)); requestAnimationFrame(step); }; step(); }
}

// ---- reveal a copy-able string (v1 displayPublicKey) ----
export async function linkReveal(intro: string, value: string): Promise<void> {
  const msg = appShell();
  const introEl = document.createElement("span"); msg.appendChild(introEl);
  await typeInto(introEl, intro, 8);
  const p = document.createElement("p"); p.textContent = value;
  p.style.cssText = "font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;line-height:1.6;word-break:break-all;background:var(--fk-fill);border-radius:10px;padding:14px 16px;margin:12px 0 0;color:var(--fk-ink-soft)";
  msg.appendChild(p);
  const copy = document.createElement("div"); copy.className = "copy_button no_select"; copy.style.marginTop = "14px";
  copy.innerHTML = `${SVG.copy.replace("<svg", '<svg class="copy_icon"')}<span class="cp_lbl">Copy</span>`;
  msg.appendChild(copy); scrollToBottom();
  copy.addEventListener("click", async () => {
    const l = copy.querySelector(".cp_lbl")!;
    try { await navigator.clipboard.writeText(value); l.textContent = "Copied!"; setTimeout(() => (l.textContent = "Copy"), 2000); }
    catch { l.textContent = "Couldn't copy. Select it above."; setTimeout(() => (l.textContent = "Copy"), 2500); }
  });
}

// ---- right-aligned input prompt with Confirm (v1 openRecipientPrompt parts) ----
/** A confirmed user entry, shown as its own right-aligned "sent" bubble (no avatar). */
function appSent(text: string): void {
  const outer = document.createElement("div");
  outer.className = "std_upload_outer";
  const b = document.createElement("div");
  b.className = "sent_msg";
  b.textContent = text;
  outer.appendChild(b);
  mainInner.appendChild(outer);
  scrollToBottom();
}
export function inputPrompt(
  fields: { key: string; placeholder: string; type?: string }[],
  validate?: (values: Record<string, string>) => string | null,
): Promise<Record<string, string>> {
  return new Promise((resolve) => {
    const cont = document.createElement("div");
    cont.className = "pub_key_textarea_cont fk_setup_cont";
    const inputs: Record<string, HTMLInputElement> = {};
    for (const f of fields) {
      const i = document.createElement("input");
      i.className = "fk_input";
      i.type = f.type ?? "text";
      i.placeholder = f.placeholder;
      i.spellcheck = false;
      inputs[f.key] = i;
      cont.appendChild(i);
    }
    const errEl = document.createElement("div");
    errEl.className = "fk_input_err";
    errEl.style.display = "none";
    cont.appendChild(errEl);
    const actions = document.createElement("div");
    actions.className = "pub_key_actions";
    const confirm = document.createElement("span");
    confirm.className = "confirm_pub_key no_select";
    confirm.innerHTML = `${SVG.check.replace("<svg", '<svg class="confirm_icon"')} <span>Confirm</span>`;
    const submit = () => {
      const out: Record<string, string> = {};
      for (const f of fields) out[f.key] = inputs[f.key]!.value.trim();
      // Validate in place: keep the form, show an inline error, let the user fix it.
      if (validate) {
        const msg = validate(out);
        if (msg) { errEl.textContent = msg; errEl.style.display = ""; inputs[fields[0]!.key]!.focus(); return; }
      }
      cont.remove();
      for (const f of fields) { const v = out[f.key]!; if (v) appSent(v); }
      resolve(out);
    };
    confirm.addEventListener("click", submit);
    actions.appendChild(confirm);
    cont.appendChild(actions);
    mainInner.appendChild(cont);
    inputs[fields[0]!.key]!.focus();
    for (const f of fields) inputs[f.key]!.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") submit(); });
    scrollToBottom();
  });
}

// ---- drop bar ----
export function showDropBar(text: string, onItems: (items: BundleItem[]) => void): void {
  const bar = $("drop_container");
  (bar.querySelector(".file_title") as HTMLElement).textContent = text;
  (bar.querySelector(".dc_icon_container") as HTMLElement).innerHTML = SVG.plus;
  setIcon(bar.querySelector(".dc_icon_container")!, "plus_icon");
  bar.style.display = "flex";
  dropOnItems = onItems;
  const fileInput = $("file_input") as HTMLInputElement;
  const folderInput = $("folder_input") as HTMLInputElement;
  ($("choose_file") as HTMLButtonElement).onclick = () => fileInput.click();
  ($("choose_folder") as HTMLButtonElement).onclick = () => folderInput.click();
  bar.onclick = (e) => { if (!(e.target as HTMLElement).closest(".dc_btn, input")) fileInput.click(); };
  fileInput.onchange = () => { if (fileInput.files?.length) onItems(collectFromInput(fileInput.files)); fileInput.value = ""; };
  folderInput.onchange = () => { if (folderInput.files?.length) onItems(collectFromInput(folderInput.files)); folderInput.value = ""; };
  // Keep the feed clear of the fixed bar however tall it wraps (mobile can be 2 rows).
  const outer = $("outer_drop_container");
  const syncPad = () => { mainInner.style.paddingBottom = `${outer.offsetHeight + 24}px`; };
  // Window-level drag listeners + the resize watcher install once; only the target changes.
  if (!dragWired) {
    dragWired = true;
    new ResizeObserver(syncPad).observe(outer);
    const dragWin = $("drag_window"), fdz = $("file_drag_zone");
    let depth = 0;
    window.addEventListener("dragenter", (e) => { e.preventDefault(); if (++depth === 1) { dragWin.style.display = "block"; fdz.style.display = "block"; } });
    window.addEventListener("dragover", (e) => e.preventDefault());
    window.addEventListener("dragleave", (e) => { e.preventDefault(); if (--depth <= 0) { depth = 0; dragWin.style.display = "none"; fdz.style.display = "none"; } });
    window.addEventListener("drop", (e) => { e.preventDefault(); depth = 0; dragWin.style.display = "none"; fdz.style.display = "none"; const dt = (e as DragEvent).dataTransfer; if (dt) void collectFromDrop(dt).then((items) => { if (items.length && dropOnItems) dropOnItems(items); }); });
  }
  syncPad();
}
export function hideDropBar(): void {
  $("drop_container").style.display = "none";
  dropOnItems = null;
}

// ---- chrome: logo + menu + appearance toggle (v1 init/initChiz) ----
export function initChrome(): void {
  mainInner = $("main_inner");
  allowAutoScroll = true;
  $("logo_bar").innerHTML = `${SVG.logo.replace("<svg", '<svg class="filekey_logo_icon"')}<span id="logo_txt">FileKey</span><span class="badge">Drop</span>`;
  $("logo_bar").addEventListener("click", () => (location.href = "/"));

  const backdrop = $("chiz_hidden_click_container");
  const menu = $("chiz_menu_container"), icon = $("chiz_icon_container");
  const set = (on: boolean) => { menu.style.display = on ? "block" : "none"; icon.classList.toggle("is-open", on); icon.setAttribute("aria-expanded", String(on)); };
  const close = () => { set(false); backdrop.style.display = "none"; };
  const toggle = () => (menu.style.display === "block" ? close() : (set(true), (backdrop.style.display = "block")));
  icon.addEventListener("click", toggle);
  icon.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
  backdrop.addEventListener("click", close);

  // Appearance: Light / Dark / Auto — verbatim from initChiz (auto follows the OS live).
  const themeMql = window.matchMedia("(prefers-color-scheme: dark)");
  let themeMode = ((): string => { try { return localStorage.getItem("filekey-theme") || "auto"; } catch { return "auto"; } })();
  const themeOpts = Array.from(document.querySelectorAll<HTMLElement>(".theme_opt"));
  const resolveTheme = (mode: string): "light" | "dark" => (mode === "dark" || (mode === "auto" && themeMql.matches) ? "dark" : "light");
  const applyTheme = (mode: string) => {
    themeMode = mode;
    const resolved = resolveTheme(mode);
    document.documentElement.dataset.theme = resolved;
    const meta = document.querySelector('meta[name="theme-color"]') as HTMLMetaElement | null;
    if (meta) meta.content = resolved === "dark" ? "#0c0c0e" : "#ffffff";
    themeOpts.forEach((el) => { const on = el.dataset.mode === mode; el.classList.toggle("active", on); el.setAttribute("aria-checked", String(on)); });
  };
  const selectTheme = (el: HTMLElement) => { const mode = el.dataset.mode || "light"; try { localStorage.setItem("filekey-theme", mode); } catch { /* in-memory only */ } applyTheme(mode); };
  applyTheme(themeMode);
  themeOpts.forEach((el, i) => {
    el.addEventListener("click", () => selectTheme(el));
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectTheme(el); }
      else if (e.key === "ArrowRight" || e.key === "ArrowDown") { e.preventDefault(); const n = themeOpts[(i + 1) % themeOpts.length]!; n.focus(); selectTheme(n); }
      else if (e.key === "ArrowLeft" || e.key === "ArrowUp") { e.preventDefault(); const p = themeOpts[(i - 1 + themeOpts.length) % themeOpts.length]!; p.focus(); selectTheme(p); }
    });
  });
  themeMql.addEventListener("change", () => { if (themeMode === "auto") applyTheme("auto"); });
  document.querySelectorAll(".plain_menu_link").forEach((a) => a.addEventListener("click", () => close()));

  marchingBorder($("drop_container"));
}
