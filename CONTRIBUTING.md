# Contributing

Thanks for helping. The most valuable contribution right now is a **test report**: run the lab from the README on your machine and open an issue with the [test report template](.github/ISSUE_TEMPLATE/test-report.yml).

## Ground rules

- Everything runs locally. The target app is deliberately vulnerable — never expose the lab to the internet.
- Traffic is synthetic. Please describe results as lab results, not real-world detection accuracy.
- Keep changes reproducible: pin image and package versions, and say how you verified a change (commands + scorer output).

## Pull requests

| Change | Please include |
|---|---|
| New or improved rule (Sigma / Wazuh) | The rule, `bash tools/check_sigma.sh` output for Sigma, and scorer output before / after on `traffic demo` |
| New attack scenario | The scenario in `traffic/lab_traffic.py`, its label (`role`), and what currently detects it (or doesn't) |
| ML model or features | Training data description, `model_meta.json`, and scorer output including normal-user false positives |
| Docs / install fixes | The OS and Docker versions where you saw the problem |

Keep the Sigma rules and the Wazuh rules giving the same verdicts (`tools/sigma_vs_wazuh.py`), or explain why they differ.
