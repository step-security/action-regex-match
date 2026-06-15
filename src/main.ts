import * as core from '@actions/core';
import fs from 'fs';
import { env } from 'process';
import * as vm from 'vm';
import axios, { isAxiosError } from 'axios';

const MAX_TEXT_LENGTH = 1_000_000;
const MAX_REGEX_LENGTH = 1000;
const REGEX_TIMEOUT_MS = 5000;

async function validateSubscription(): Promise<void> {
  const eventPath = env.GITHUB_EVENT_PATH;
  let repoPrivate;
  if (eventPath && fs.existsSync(eventPath)) {
    const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
    repoPrivate = eventData?.repository?.private;
  }

  const upstream = 'actions-ecosystem/action-regex-match';
  const action = env.GITHUB_ACTION_REPOSITORY;
  const docsUrl =
    'https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions';

  core.info('');
  core.info('\u001b[1;36mStepSecurity Maintained Action\u001b[0m');
  core.info(`Secure drop-in replacement for ${upstream}`);
  if (repoPrivate === false)
    core.info('\u001b[32m\u2713 Free for public repositories\u001b[0m');
  core.info(`\u001b[36mLearn more:\u001b[0m ${docsUrl}`);
  core.info('');

  if (repoPrivate === false) return;

  const serverUrl = env.GITHUB_SERVER_URL || 'https://github.com';
  const body: Record<string, string> = { action: action || '' };
  if (serverUrl !== 'https://github.com') body.ghes_server = serverUrl;
  const repository = env.GITHUB_REPOSITORY ?? '';

  try {
    await axios.post(
      `https://agent.api.stepsecurity.io/v1/github/${repository}/actions/maintained-actions-subscription`,
      body,
      { timeout: 3000 }
    );
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 403) {
      core.error(
        '\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m'
      );
      core.error(
        `\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`
      );
      process.exit(1);
    }
    core.info('Timeout or API not reachable. Continuing to next step.');
  }
}

async function run(): Promise<void> {
  try {
    await validateSubscription();
    const text = core.getInput('text');
    const regex = core.getInput('regex');
    const flags = core.getInput('flags');

    if (text.length > MAX_TEXT_LENGTH) {
      core.setFailed(
        `Input 'text' exceeds maximum length of ${MAX_TEXT_LENGTH} characters`
      );
      return;
    }

    if (regex.length > MAX_REGEX_LENGTH) {
      core.setFailed(
        `Input 'regex' exceeds maximum length of ${MAX_REGEX_LENGTH} characters`
      );
      return;
    }

    const re = new RegExp(regex, flags);

    const result = vm.runInNewContext(
      're.exec(text)',
      { re, text },
      { timeout: REGEX_TIMEOUT_MS }
    ) as RegExpExecArray | null;

    if (result) {
      for (const [index, x] of result.entries()) {
        if (index === 10) {
          return;
        }

        if (index === 0) {
          core.setOutput('match', x);
          continue;
        }

        core.setOutput(`group${index}`, x);
      }
    }
  } catch (error: unknown) {
    if (error instanceof Error && error.message.includes('timed out')) {
      core.setFailed(
        'Regex execution timed out — the pattern may cause catastrophic backtracking'
      );
      return;
    }
    if (error instanceof Error) {
      core.error(error);
      core.setFailed(error.message);
    } else {
      core.setFailed(String(error));
    }
  }
}

run();
