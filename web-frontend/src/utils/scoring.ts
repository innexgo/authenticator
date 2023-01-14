export function scorePrisonersDilemma(submission_defected: boolean, opponent_submission_defected: boolean) {
    if(submission_defected) {
        if(opponent_submission_defected) {
            // both defect
            return 5;
        } else {
            // you defect, partner cooperates
            return 10;
        }
    } else {
        if(opponent_submission_defected) {
            // you cooperate, your partner defects
            return 0;
        } else {
            // both cooperate
            return 8;
        }
    }
}
