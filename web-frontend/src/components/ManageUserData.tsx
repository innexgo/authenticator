import React from 'react';
import { Table } from 'react-bootstrap';
import { Action, DisplayModal } from '@innexgo/common-react-components';
import { Pencil, Lock, EnvelopePlus, BoxArrowRight } from 'react-bootstrap-icons';
import {format} from 'date-fns/format';
import { UserData, Email, ApiKey } from '@innexgo/frontend-auth-api';

import EditUserDataForm from '../components/EditUserDataForm';
import SendVerificationChallengeForm from '../components/SendVerificationChallengeForm';
import ManagePassword from '../components/ManagePassword';
import {differenceInYears} from 'date-fns/differenceInYears';

const ManageUserData = (props: {
  userData: UserData,
  setUserData: (userData: UserData) => void,
  ownEmail?: Email,
  parentEmail?: Email,
  apiKey: ApiKey,
  setApiKey: (a: ApiKey | null) => void,
}) => {
  const [sentOwnEmail, setSendOwnEmail] = React.useState(false);
  const [sentParentEmail, setSendParentEmail] = React.useState(false);

  const [showEditUserData, setShowEditUserData] = React.useState(false);
  const [showChangeOwnEmail, setShowChangeOwnEmail] = React.useState(false);
  const [showChangeParentEmail, setShowChangeParentEmail] = React.useState(false);
  const [showChangePassword, setShowChangePassword] = React.useState(false);

  const editOwnEmailString =
    props.ownEmail === undefined ? "Add Email Address" : "Change Email Address";

  const editParentEmailString = props.parentEmail === undefined ? "Set Parent Email" : "Change Parent Email";

  const shouldShowParentEmail = props.parentEmail !== undefined || (Date.now() - props.userData.dateofbirth) <= 13 * 365 * 24 * 60 * 60 * 1000;

  return <>
    <Table hover bordered>
      <tbody>
        <tr>
          <th>Name</th>
          <td>{props.userData.realname}</td>
        </tr>
        <tr>
          <th>Username</th>
          <td>{props.userData.username}</td>
        </tr>
        <tr>
          <th>Date of Birth</th>
          <td>{format(props.userData.dateofbirth, 'MMM do, yyyy')}</td>
        </tr>
        <tr>
          <th>Email Address</th>
          <td>
            <table>
              <tr>
                <td>
                  {props.ownEmail?.verificationChallenge.email ?? "N/A"}
                  {sentOwnEmail ? <span className="text-danger">*</span> : null}
                </td>
              </tr>
              {
                sentOwnEmail
                  ? <tr>
                    <td>
                      <small className="text-muted">Check your email for instructions to finish the process.</small>
                    </td>
                  </tr>
                  : null
              }
            </table>
          </td>
        </tr>
        {shouldShowParentEmail
          ? <tr>
            <th>Parent Email</th>
            <td>
              <table>
                <tr>
                  <td>
                    {props.parentEmail?.verificationChallenge.email ?? "N/A"}
                    {sentParentEmail ? <span className="text-danger">*</span> : null}
                  </td>
                </tr>
                {
                  sentParentEmail
                    ? <tr>
                      <td>
                        <small className="text-muted">Your parent must complete the instructions in the email to finish the process.</small>
                      </td>
                    </tr>
                    : null
                }
              </table>
            </td>
          </tr>
          : null
        }
      </tbody>
    </Table>
    <div className='d-flex' >
      <Action
        title="Edit Personal Information"
        icon={Pencil}
        onClick={() => setShowEditUserData(true)}
      />
      <Action
        title={editOwnEmailString}
        icon={EnvelopePlus}
        onClick={() => setShowChangeOwnEmail(true)}
      />
      {shouldShowParentEmail
        ? <Action
          title={editParentEmailString}
          icon={EnvelopePlus}
          onClick={() => setShowChangeParentEmail(true)}
        />
        : null
      }
      <Action
        title="Change Password"
        icon={Lock}
        onClick={() => setShowChangePassword(true)}
      />
      <div className='ms-auto'>
        <Action
          title="Log Out"
          icon={BoxArrowRight}
          onClick={() => props.setApiKey(null)}
        />
      </div>
    </div>

    <DisplayModal
      title="Edit Personal Information"
      show={showEditUserData}
      onClose={() => setShowEditUserData(false)}
    >
      <EditUserDataForm
        userData={props.userData}
        apiKey={props.apiKey}
        setUserData={userData => {
          setShowEditUserData(false);
          props.setUserData(userData);
        }}
      />
    </DisplayModal>
    <DisplayModal
      title="Change Password"
      show={showChangePassword}
      onClose={() => setShowChangePassword(false)}
    >
      <ManagePassword
        apiKey={props.apiKey}
        onSuccess={() => {
          setShowChangePassword(false);
        }}
      />
    </DisplayModal>
    <DisplayModal
      title={editOwnEmailString}
      show={showChangeOwnEmail}
      onClose={() => setShowChangeOwnEmail(false)}
    >
      <SendVerificationChallengeForm
        toParent={false}
        initialEmailAddress={props.ownEmail?.verificationChallenge.email ?? ""}
        apiKey={props.apiKey}
        setVerificationChallenge={() => { setShowChangeOwnEmail(false); setSendOwnEmail(true) }}
      />
    </DisplayModal>
    <DisplayModal
      title={editParentEmailString}
      show={showChangeParentEmail}
      onClose={() => setShowChangeParentEmail(false)}
    >
      <SendVerificationChallengeForm
        toParent={true}
        initialEmailAddress={props.parentEmail?.verificationChallenge.email ?? ""}
        apiKey={props.apiKey}
        setVerificationChallenge={() => { setShowChangeParentEmail(false); setSendParentEmail(true) }}
      />
    </DisplayModal>

  </>
}

export default ManageUserData;
