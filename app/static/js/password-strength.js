function initPasswordStrength(options) {
  const input = document.getElementById(options.inputId);
  const box = document.getElementById("strength-box");
  const bitsEl = document.getElementById("strength-bits");
  const fillEl = document.getElementById("strength-fill");
  const statusEl = document.getElementById("strength-status");
  const hintsEl = document.getElementById("live-hints");
  if (!input || !box || !bitsEl || !fillEl || !statusEl || !hintsEl) {
    return;
  }

  let timer = null;

  function render(data) {
    box.hidden = false;
    bitsEl.textContent = `${data.bits} bitów`;
    const ratio = Math.max(0, Math.min(1, data.bits / Math.max(options.minBits, 1)));
    fillEl.style.width = `${Math.round(ratio * 100)}%`;
    fillEl.className = data.ok ? "strength-fill ok" : "strength-fill weak";

    if (!data.length_ok) {
      statusEl.textContent = `Za krótkie (min. ${options.minLength} znaków).`;
      statusEl.className = "strength-status weak";
    } else if (options.policyEnabled && !data.entropy_ok) {
      statusEl.textContent = `Poniżej progu ${options.minBits} bitów.`;
      statusEl.className = "strength-status weak";
    } else if (options.policyEnabled) {
      statusEl.textContent = "Hasło spełnia wymaganą siłę.";
      statusEl.className = "strength-status ok";
    } else {
      statusEl.textContent = "Podpowiedzi siły (polityka entropii wyłączona).";
      statusEl.className = "strength-status";
    }

    hintsEl.innerHTML = "";
    (data.hints || []).forEach((hint) => {
      const li = document.createElement("li");
      li.textContent = hint;
      hintsEl.appendChild(li);
    });
  }

  async function evaluate() {
    const password = input.value || "";
    if (!password) {
      box.hidden = true;
      return;
    }
    try {
      const response = await fetch(options.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": options.csrfToken,
        },
        body: JSON.stringify({ password }),
      });
      if (!response.ok) {
        return;
      }
      const data = await response.json();
      render(data);
    } catch (_err) {
      // Keep the form usable if live feedback fails.
    }
  }

  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(evaluate, 250);
  });
}
