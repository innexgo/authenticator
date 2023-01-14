import { fetchApi, Result, apiUrl } from '@innexgo/frontend-common'

export type TournamentSubmissionKind =
  "COMPETE" |
  "VALIDATE" |
  "TESTCASE" |
  "CANCEL";

export type Submission = {
  submissionId: number,
  creationTime: number,
  creatorUserId: number,
  code: string,
}

export type Tournament = {
  tournamentId: number,
  creationTime: number,
  creatorUserId: number,
}

export type TournamentData = {
  tournamentDataId: number,
  creationTime: number,
  creatorUserId: number,
  tournament: Tournament,
  title: string,
  description: string,
  nRounds: number,
  nMatchups: number,
  active: boolean,
}

export type TournamentSubmission = {
  tournamentSubmissionId: number,
  creationTime: number,
  creatorUserId: number,
  tournament: Tournament,
  submissionId: number,
  name: string,
  kind: TournamentSubmissionKind,
}

export type MatchResolution = {
  matchResolutionId: number,
  creationTime: number,
  submissionId: number,
  opponentSubmissionId: number,
  round: number,
  matchup: number,
  defected: boolean | null,
  stdout: string,
  stderr: string,
}

export type MatchResolutionLite = {
  matchResolutionId: number,
  creationTime: number,
  submissionId: number,
  opponentSubmissionId: number,
  round: number,
  matchup: number,
  defected: boolean | null,
}


export const AppErrorCodes = [
  "NO_CAPABILITY",
  "SUBMISSION_NONEXISTENT",
  "TOURNAMENT_NONEXISTENT",
  "TOURNAMENT_DATA_N_ROUNDS_INVALID",
  "TOURNAMENT_DATA_N_MATCHUPS_INVALID",
  "TOURNAMENT_DATA_TOO_MANY_MATCHES",
  "SUBMISSION_TOO_LONG",
  "TOURNAMENT_SUBMISSION_NOT_VALIDATED",
  "TOURNAMENT_SUBMISSION_TESTCASE_INCOMPLETE",
  "TOURNAMENT_SUBMISSION_TESTCASE_FAILS",
  "TOURNAMENT_ARCHIVED",
  "STREAM_END_BEFORE_REQUEST",
  "DECODE_ERROR",
  "METHOD_NOT_ALLOWED",
  "INTERNAL_SERVER_ERROR",
  "UNAUTHORIZED",
  "BAD_REQUEST",
  "NOT_FOUND",
  "NETWORK",
  "UNKNOWN",
] as const;

// Creates a union export type
export type AppErrorCode = typeof AppErrorCodes[number];

async function fetchApiOrNetworkError<T>(url: string, props: object): Promise<Result<T, AppErrorCode>> {
  try {
    const [code, resp] = await fetchApi(url, props);
    if (code >= 200 && code < 300) {
      return { Ok: resp }
    } else {
      return { Err: resp }
    }
  } catch (_) {
    return { Err: "NETWORK" };
  }
}

const undefToStr = (s: string | undefined) =>
  s === undefined ? apiUrl() : s

export type SubmissionNewProps = {
  code: string,
  apiKey: string,
}

export function submissionNew(props: SubmissionNewProps, server?: string): Promise<Result<Submission, AppErrorCode>> {
  return fetchApiOrNetworkError(undefToStr(server) + "pdarena/submission/new", props);
}


export type TournamentNewProps = {
  title: string,
  description: string,
  apiKey: string,
  nRounds: number,
  nMatchups: number,
}

export function tournamentNew(props: TournamentNewProps, server?: string): Promise<Result<TournamentData, AppErrorCode>> {
  return fetchApiOrNetworkError(undefToStr(server) + "pdarena/tournament/new", props);
}

export type TournamentDataNewProps = {
  tournamentId: number,
  title: string,
  description: string,
  nRounds: number,
  nMatchups: number,
  active: boolean,
  apiKey: string,
}

export function tournamentDataNew(props: TournamentDataNewProps, server?: string): Promise<Result<TournamentData, AppErrorCode>> {
  return fetchApiOrNetworkError(undefToStr(server) + "pdarena/tournament_data/new", props);
}


export type TournamentSubmissionNewProps = {
  tournamentId: number,
  submissionId: number,
  kind: TournamentSubmissionKind,
  name: string,
  apiKey: string,
}

export function tournamentSubmissionNew(props: TournamentSubmissionNewProps, server?: string): Promise<Result<TournamentSubmission, AppErrorCode>> {
  return fetchApiOrNetworkError(undefToStr(server) + "pdarena/tournament_submission/new", props);
}

export type SubmissionViewProps = {
  submissionId?: number[],
  minCreationTime?: number,
  maxCreationTime?: number,
  creatorUserId?: number[],
  apiKey: string,
}

export function submissionView(props: SubmissionViewProps, server?: string): Promise<Result<Submission[], AppErrorCode>> {
  return fetchApiOrNetworkError(undefToStr(server) + "pdarena/submission/view", props);
}


export type TournamentDataViewProps = {
  tournamentDataId?: number[],
  minCreationTime?: number,
  maxCreationTime?: number,
  creatorUserId?: number[],
  tournamentId?: number[],
  title?: string[],
  active?: boolean,
  onlyRecent: boolean,
  apiKey: string,
}

export function tournamentDataView(props: TournamentDataViewProps, server?: string): Promise<Result<TournamentData[], AppErrorCode>> {
  return fetchApiOrNetworkError(undefToStr(server) + "pdarena/tournament_data/view", props);
}

export type TournamentSubmissionViewProps = {
  tournamentSubmissionId?: number[],
  minCreationTime?: number,
  maxCreationTime?: number,
  creatorUserId?: number[],
  tournamentId?: number[],
  submissionId?: number[],
  kind?: TournamentSubmissionKind,
  onlyRecent: boolean,
  apiKey: string,
}

export function tournamentSubmissionView(props: TournamentSubmissionViewProps, server?: string): Promise<Result<TournamentSubmission[], AppErrorCode>> {
  return fetchApiOrNetworkError(undefToStr(server) + "pdarena/tournament_submission/view", props);
}

export type MatchResolutionViewProps = {
  minCreationTime?: number,
  maxCreationTime?: number,
  minId?: number,
  maxId?: number,
  matchResolutionId?: number[],
  submissionId?: number[],
  opponentSubmissionId?: number[],
  round?: number[],
  matchup?: number[],
  onlyRecent: boolean,
  apiKey: string,
}

export function matchResolutionView(props: MatchResolutionViewProps, server?: string): Promise<Result<MatchResolution[], AppErrorCode>> {
  return fetchApiOrNetworkError(undefToStr(server) + "pdarena/match_resolution/view", props);
}

function wsRelativeUrl(relPath: string) {
  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${protocol}://${window.location.host}/api/${relPath}`
}

export function matchResolutionLiteStream(props: MatchResolutionViewProps, server?: string): WebSocket {
  const path = "pdarena/ws/match_resolution_lite/stream";
  const url = server === undefined
    ? wsRelativeUrl(path)
    : server + path;
  const ws = new WebSocket(url);
  ws.addEventListener('open', () => ws.send(JSON.stringify(props)));
  return ws;
}
