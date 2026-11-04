// RAJDOLL's own script (CSP: script-src 'self'). Copy buttons: data-copy="<selector>".
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const source = document.querySelector(button.dataset.copy);
  if (!source) return;
  const original = button.textContent;
  const done = (label) => {
    button.textContent = label;
    setTimeout(() => { button.textContent = original; }, 1500);
  };
  navigator.clipboard.writeText(source.textContent).then(
    () => done("Tersalin"),
    () => done("Gagal menyalin"),
  );
});
