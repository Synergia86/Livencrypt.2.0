// SPDX-License-Identifier: GPL-3.0-or-later

import logoUrl from "../../../src-tauri/icons/livencrypt2.0_logo.png";

export default function LivencryptIcon({ size = 28, darkMode = true }: { size?: number; darkMode?: boolean }) {
  const shadow = darkMode
    ? "drop-shadow(0 0 10px rgba(6, 182, 212, 0.45))"
    : "drop-shadow(0 0 8px rgba(8, 145, 178, 0.28))";

  return (
    <img
      src={logoUrl}
      alt="Livencrypt 2.0"
      width={size}
      height={size}
      className="object-contain transition-transform duration-300 hover:scale-105"
      style={{ filter: shadow }}
      draggable={false}
    />
  );
}
