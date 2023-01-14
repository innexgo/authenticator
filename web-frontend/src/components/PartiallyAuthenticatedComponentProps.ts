import { ApiKey } from '@innexgo/frontend-auth-api';
import { Branding } from '@innexgo/common-react-components';

export default interface PartiallyAuthenticatedComponentProps {
  // other branding stuff
  branding: Branding,
  // api key
  apiKey: ApiKey,
  // function to set the api key
  setApiKey: (data: ApiKey | null) => void,
}
