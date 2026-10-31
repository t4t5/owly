const copyButton = document.querySelector('.copy');
copyButton?.addEventListener('click', async () => {
  const commands = document.querySelector('.terminal code')?.textContent;
  if (!commands) return;
  try {
    await navigator.clipboard.writeText(commands);
    copyButton.textContent = 'COPIED';
    window.setTimeout(() => { copyButton.textContent = 'COPY COMMANDS'; }, 1800);
  } catch {
    copyButton.textContent = 'SELECT TEXT ABOVE';
  }
});
