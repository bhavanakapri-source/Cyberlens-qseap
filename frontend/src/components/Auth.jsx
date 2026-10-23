import { useState } from "react";
import Logo from "./Logo";

const API_URL =os.getenv("HUGGING_FACE_API");

function Auth({ onLogin, notice }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const endpoint = "/api/auth/login";
      const body = { email, password };

      const response = await fetch(
        `${API_URL}${endpoint}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "Please check your details and try again."
        );
      }

      localStorage.setItem(
        "cyberlens_token",
        data.access_token
      );

      localStorage.setItem(
        "cyberlens_user",
        JSON.stringify(data.user)
      );

      onLogin(data.user);

    } catch (err) {
      setError(
        err instanceof TypeError
          ? "Unable to connect to CyberLens. Please check that the backend is running."
          : err.message
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <section
        className="auth-hero"
        aria-label="About CyberLens"
      >
        <div
          className="radar"
          aria-hidden="true"
        >
          <span className="ring r1" />
          <span className="ring r2" />
          <span className="ring r3" />
          <span className="sweep" />

          <span className="radar-core">
            <Logo size={46} />
          </span>
        </div>

        <div className="hero-copy">
          <h1>CyberLens</h1>

          <p className="hero-title">
            AI-powered vulnerability intelligence
          </p>

          <p className="hero-lines">
            Investigate vulnerabilities.
            <br />
            Understand risk.
            <br />
            Remediate with confidence.
          </p>
        </div>
      </section>

      <section className="auth-side">
        <div className="auth-card">

          <div className="auth-card-brand">
            <Logo size={22} />
            CyberLens
          </div>

         <h2>Welcome back</h2>

          <p className="auth-lead">
            Continue your security investigation.
          </p>

          {notice && !error && (
            <div
              className="alert alert-info"
              role="status"
            >
              {notice}
            </div>
          )}

          <form onSubmit={handleSubmit}>

            <div className="field">
              <label htmlFor="auth-email">
                Email
              </label>

              <input
                id="auth-email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) =>
                  setEmail(e.target.value)
                }
                placeholder="you@company.com"
                required
              />
            </div>

            <div className="field">
              <label htmlFor="auth-password">
                Password
              </label>

              <input
                id="auth-password"
                type="password"
                value={password}
                autoComplete="current-password"
                onChange={(e) =>
                  setPassword(e.target.value)
                }
                placeholder="Enter your password"
                required
                minLength={6}
              />
            </div>

            {error && (
              <div
                className="alert alert-error"
                role="alert"
              >
                {error}
              </div>
            )}

            <button
              type="submit"
              className="btn-primary"
              disabled={loading}
            >
              {loading ? "Please wait…" : "Sign in"}
            </button>

          </form>

        </div>
      </section>
    </div>
  );
}

export default Auth;