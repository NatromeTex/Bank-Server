# Mathematical Formulation of the DDoS Detection and Mitigation System

---

## 1. Risk Score Function

$$R(p,\, \lambda) = \min\!\left(0.6\, p + 0.4\, \hat{\lambda},\; 1\right)$$

**Variables:**
- $p \in [0, 1]$ — ML-predicted attack probability for a given flow
- $\lambda$ — observed request rate (packets per second) for the flow
- $\hat{\lambda}$ — log-scaled, baseline-normalized rate component (defined in §2)

---

## 2. Request Rate Normalization (Log Scaling)

The raw request rate is derived from the CICFlowMeter-compatible bidirectional flow record:

$$\lambda = \frac{N_{\text{fwd}} + N_{\text{bwd}}}{\max\!\left(\dfrac{D_{\mu s}}{10^6},\; \varepsilon\right)}$$

It is then normalized against a baseline using a logarithmic transform to compress heavy-tail distributions:

$$\hat{\lambda} = \frac{\ln(1 + \lambda)}{\ln(1 + \lambda_0)}$$

**Variables:**
- $N_{\text{fwd}},\, N_{\text{bwd}}$ — forward and backward packet counts from the flow record (`fwd_packets`, `bwd_packets`)
- $D_{\mu s}$ — flow duration in microseconds (`flow_duration_us`)
- $\varepsilon = 10^{-6}$ — minimum duration guard against division by zero
- $\lambda_0 = 50.0$ — baseline request rate (packets per second)
- $\hat{\lambda} \in [0, \infty)$ — normalized rate; equals $1$ when $\lambda = \lambda_0$

---

## 3. EMA Risk Smoothing

Per-IP risk scores are smoothed across evaluation cycles using an Exponential Moving Average (EMA) to reduce noise from transient spikes:

$$\widetilde{R}_t(i) = \alpha\, R_t(i) + (1 - \alpha)\, \widetilde{R}_{t-1}(i)$$

**Initialization:** $\widetilde{R}_0(i) = R_0(i)$ (first observation is used as-is)

**Variables:**
- $i$ — source IP address identifier
- $t$ — discrete evaluation cycle index
- $R_t(i)$ — raw risk score for IP $i$ at cycle $t$, computed via §1
- $\widetilde{R}_t(i)$ — EMA-smoothed risk score for IP $i$ at cycle $t$
- $\alpha = 0.7$ — smoothing factor; higher values weight recent observations more heavily

---

## 4. Risk Tier Classification

The smoothed risk score is mapped to a discrete severity tier via a piecewise threshold function:

$$T\!\left(\widetilde{R}\right) = \begin{cases} \text{HIGH}     & \text{if } \widetilde{R} \geq 0.70 \\ \text{MODERATE} & \text{if } 0.35 \leq \widetilde{R} < 0.70 \\ \text{LOW}      & \text{if } \widetilde{R} < 0.35 \end{cases}$$

**Variables:**
- $\widetilde{R} \in [0,1]$ — EMA-smoothed risk score from §3
- $T(\widetilde{R}) \in \{\text{LOW},\, \text{MODERATE},\, \text{HIGH}\}$ — resulting risk tier

---

## 5. Persistence-Based Escalation

A per-IP counter tracks consecutive HIGH-tier evaluations. The counter is incremented on each HIGH classification and reset to zero otherwise:

$$c_t(i) = \begin{cases} c_{t-1}(i) + 1 & \text{if } T\!\left(\widetilde{R}_t(i)\right) = \text{HIGH} \\ 0 & \text{otherwise} \end{cases}$$

The enforcement action is determined jointly by the tier and the sustained-high counter:

$$A(i) = \begin{cases} \text{block}       & \text{if } T\!\left(\widetilde{R}\right) = \text{HIGH} \;\wedge\; c(i) \geq \kappa \\ \text{rate\_limit} & \text{if } T\!\left(\widetilde{R}\right) = \text{HIGH} \;\wedge\; c(i) < \kappa \\ \text{rate\_limit} & \text{if } T\!\left(\widetilde{R}\right) = \text{MODERATE} \\ \text{allow}       & \text{if } T\!\left(\widetilde{R}\right) = \text{LOW} \end{cases}$$

**Variables:**
- $c_t(i) \in \mathbb{Z}_{\geq 0}$ — consecutive HIGH-tier evaluation count for IP $i$ up to cycle $t$
- $\kappa = 3$ — minimum number of consecutive HIGH evaluations required to trigger a block
- $A(i)$ — enforcement action applied to IP $i$

---

## 6. ML Confidence Aggregation

Within a sliding time window $W$, the per-alert risk scores $\{R_1, R_2, \ldots, R_n\}$ are aggregated into a single ML confidence signal using a weighted combination of the peak and mean:

$$C_{\text{ML}} = \begin{cases} \max\!\left(0.7 \cdot \max_{i}\, R_i \;+\; 0.3 \cdot \bar{R},\;\; \delta \cdot \mathbf{1}_{\text{det}}\right) & \text{if } n > 0 \\ 0 & \text{if } n = 0 \end{cases}$$

where the mean risk is:

$$\bar{R} = \frac{1}{n} \sum_{i=1}^{n} R_i$$

**Variables:**
- $n$ — number of critical alerts observed within window $W$ (default $|W| = 10\,\text{s}$)
- $R_i = R(p_i, \lambda_i)$ — risk score of the $i$-th critical alert, computed via §1
- $\bar{R}$ — arithmetic mean of alert risk scores within $W$
- $\delta = 0.65$ — minimum confidence floor applied when an explicit attack label is present
- $\mathbf{1}_{\text{det}} \in \{0, 1\}$ — indicator variable; equals $1$ when at least one alert in $W$ carries an explicit "Attack Detected" label

---

## 7. Signal Normalization (Linear Clamp)

A shared linear-clamp function maps a raw signal $x$ onto $[0, 1]$ given lower and upper saturation bounds:

$$\sigma(x;\, x_{\text{lo}},\, x_{\text{hi}}) = \operatorname{clamp}\!\left(\frac{x - x_{\text{lo}}}{x_{\text{hi}} - x_{\text{lo}}},\; 0,\; 1\right)$$

$$\operatorname{clamp}(u,\, a,\, b) = \max\!\left(a,\, \min(b,\, u)\right)$$

**Variables:**
- $x$ — raw input value
- $x_{\text{lo}},\, x_{\text{hi}}$ — lower and upper saturation thresholds; output is $0$ below $x_{\text{lo}}$ and $1$ above $x_{\text{hi}}$

---

## 8. Composite Score and Signal Derivations

The final composite threat score aggregates four normalized signals via a fixed weighted sum:

$$S = w_{\text{ml}}\, C_{\text{ML}} \;+\; w_v\, V \;+\; w_e\, E \;+\; w_h\, H$$

with weights $w_{\text{ml}} = 0.40$,\; $w_v = 0.25$,\; $w_e = 0.20$,\; $w_h = 0.15$ (summing to $1$).

**Volume signal** — normalized flow arrival rate:

$$V = \sigma\!\left(f;\; f_{\text{sus}},\; f_{\text{atk}}\right), \qquad f_{\text{sus}} = 500\,\text{fps},\quad f_{\text{atk}} = 1500\,\text{fps}$$

**Entropy signal** — inverted source-IP entropy (low entropy implies traffic concentration):

$$E = 1 - \operatorname{clamp}\!\left(\frac{H_s}{H_{\max}},\; 0,\; 1\right), \qquad H_{\max} = 4.0\,\text{bits}$$

**Health signal** — equal-weighted combination of TPM and latency degradation relative to baseline:

$$H = \frac{1}{2}\,\sigma\!\left(\frac{\tau}{\tau_0} - 1;\; 0,\; 4\right) \;+\; \frac{1}{2}\,\sigma\!\left(\frac{\ell}{\ell_0} - 1;\; 0,\; 4\right)$$

**Variables:**
- $S \in [0, 1]$ — composite threat score used by the FSM for state transitions
- $f$ — observed flows per second
- $H_s$ — Shannon entropy of source IP addresses in the current observation window
- $\tau,\, \tau_0$ — current and baseline transactions per minute (TPM)
- $\ell,\, \ell_0$ — current and baseline average request latency (seconds)
- Saturation factor $4$ for ratio signals implies full health degradation at $5\times$ the baseline value
