# Running CI on our own machine

## Why

A private repository has 2000 free Actions minutes a month, and macOS bills at 10× and Windows at
2×. One busy day exhausted it, and once it is gone **every** job fails in three seconds with no
logs — Linux included. A self-hosted runner removes the meter.

## The rule that matters

**Detach the runner before this repository is made public.** On a public repository anyone can open
a pull request, and a pull request runs workflow code — on our machine. That is not a theoretical
risk, it is the documented reason GitHub tells you not to do it. `vars.RUNNER_LABEL` exists so
switching back is one setting, not eight edits.

## Where

`crm` (<runner-host>, user `eszetael`). Chosen for headroom rather than affinity: at the time it had
28 GB of RAM and 200 GB of disk free against `app` sitting at 80% disk — already the threshold where
the night crew starts deleting things — and `brain`, which orchestrates everything else and should
not be competing with a six-version PostgreSQL matrix.

## What is already installed

- `rustup` — a **user** install under `~/.cargo`, no root. The toolchain itself comes from
  `rust-toolchain.toml` on first build.
- The runner, unpacked in `~/actions-runner` (about 674 MB).

Nothing needed `sudo`, and nothing should: the workflows seed their fixtures through a container
rather than a `psql` on the host, precisely so the machine stays ordinary.

## What is left

Register it. The registration token is short-lived and is generated in the repository under
**Settings → Actions → Runners → New self-hosted runner**:

```bash
ssh -i ~/.ssh/<ssh-key> <user>@<runner-host>
cd ~/actions-runner
./config.sh --url https://github.com/Eszetael/postgres-mcp-hardened \
            --token <TOKEN FROM THAT PAGE> \
            --name crm-runner --labels self-hosted,linux,x64,crm --unattended --replace
```

Then run it as a **user** service — `linger` is already enabled on that account, so it survives a
reboot without root:

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/gh-runner.service <<'UNIT'
[Unit]
Description=GitHub Actions runner (postgres-mcp-hardened)
After=network-online.target

[Service]
ExecStart=%h/actions-runner/run.sh
WorkingDirectory=%h/actions-runner
Restart=always
RestartSec=10
Environment=PATH=%h/.cargo/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload && systemctl --user enable --now gh-runner
systemctl --user status gh-runner --no-pager | head -5
```

Finally, point the workflows at it by setting a repository variable
(**Settings → Secrets and variables → Actions → Variables**):

```
RUNNER_LABEL = self-hosted
```

Unset that variable and everything goes back to GitHub-hosted runners. That is the whole switch.

## Removing it

```bash
systemctl --user disable --now gh-runner
cd ~/actions-runner && ./config.sh remove --token <REMOVAL TOKEN>
```

and unset `RUNNER_LABEL`. Do this **before** the repository becomes public, not after.
