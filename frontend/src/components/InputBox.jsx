import { useRef, useState } from "react";
import Icon from "./Icons";

function InputBox({ onSend, disabled }) {
  const [value, setValue] = useState("");
  const ref = useRef(null);

  const resize = () => {
    const el = ref.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 200)}px`;
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!value.trim() || disabled) return;
    onSend(value);
    setValue("");
    requestAnimationFrame(() => { if (ref.current) ref.current.style.height = "auto"; });
  };

  const handleKeyDown = (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      handleSubmit(event);
    }
  };

  return (
    <div className="input-area">
      <form className="command-bar" onSubmit={handleSubmit}>
        <span className="command-icon"><Icon name="shieldCheck" size={20} /></span>
        <label htmlFor="chat-input" className="sr-only">Ask CyberLens</label>
        <textarea id="chat-input" ref={ref} rows={1} value={value} disabled={disabled}
          onChange={(e) => { setValue(e.target.value); resize(); }}
          onKeyDown={handleKeyDown}
          placeholder="Ask about a CVE, vulnerability, product or remediation…" />
        <button type="submit" className="send-button" disabled={disabled || !value.trim()} aria-label="Send message">
          <Icon name="send" />
        </button>
      </form>
      <div className="input-hint">Enter to send · Shift + Enter for new line</div>
    </div>
  );
}

export default InputBox;