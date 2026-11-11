(function() {
  const byId = function(id) { return document.getElementById(id); };
  const password = byId('password') || byId('new_password');
  const confirmation = byId('confirm_password') || byId('confirm_new_password');
  const submit = byId('submit-btn') || byId('profile-submit');
  const lengthMsg = byId('pw-length-msg');
  const matchMsg = byId('pw-match-msg');
  if (!password) return;
  const minLength = Number(password.dataset.minLength);

  function validate() {
    const pw = password.value;
    const cpw = confirmation ? confirmation.value : '';
    const tooShort = pw.length > 0 && pw.length < minLength;
    const mismatch = cpw.length > 0 && pw !== cpw;
    if (lengthMsg) lengthMsg.style.display = tooShort ? 'block' : 'none';
    if (matchMsg) matchMsg.style.display = mismatch ? 'block' : 'none';
    if (submit) submit.disabled = tooShort || mismatch;
    password.style.borderColor = tooShort ? 'var(--critical)' : '';
    if (confirmation) confirmation.style.borderColor = mismatch ? 'var(--critical)' : '';
  }

  password.addEventListener('input', validate);
  if (confirmation) confirmation.addEventListener('input', validate);
})();
