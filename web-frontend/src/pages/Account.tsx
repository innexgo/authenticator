import React from 'react';
import { Async, AsyncProps } from 'react-async';

import ErrorMessage from '../components/ErrorMessage';
import update from 'immutability-helper';

import { Row, Container, Col, Spinner } from 'react-bootstrap';
import SidebarLayout from '../components/SidebarLayout';
import { Section, WidgetWrapper } from '@innexgo/common-react-components';

import { ApiKey, UserData, Email, userDataView, emailView } from '@innexgo/frontend-auth-api'

import ManageUserData from '../components/ManageUserData';

import { unwrap, getFirstOr } from '@innexgo/frontend-common';
import PartiallyAuthenticatedComponentProps from '../components/PartiallyAuthenticatedComponentProps';

type AccountData = {
  userData: UserData
  ownEmail: Email|undefined
  parentEmail: Email|undefined
}

const loadAccountData = async (props: AsyncProps<AccountData>) => {
  const userData = await userDataView({
    creatorUserId: [props.apiKey.creatorUserId],
    onlyRecent: true,
    apiKey: props.apiKey.key,
  })
    .then(unwrap)
    .then(x => getFirstOr(x, "NOT_FOUND"))
    .then(unwrap);

  const ownEmail = await emailView({
    creatorUserId: [props.apiKey.creatorUserId],
    toParent: false,
    onlyRecent: true,
    apiKey: props.apiKey.key,
  })
    .then(unwrap)
    .then(x => x.at(0));

  const parentEmail = await emailView({
    creatorUserId: [props.apiKey.creatorUserId],
    toParent: true,
    onlyRecent: true,
    apiKey: props.apiKey.key,
  })
    .then(unwrap)
    .then(x => x.at(0));

  return {
    userData,
    ownEmail,
    parentEmail,
  }
}

function AccountWrapper(props: PartiallyAuthenticatedComponentProps) {
  return <SidebarLayout branding={props.branding}>
    <Async promiseFn={loadAccountData} apiKey={props.apiKey}>
      {({ setData }) => <>
        <Async.Pending>
          <Spinner animation="border" role="status">
            <span className="visually-hidden">Loading...</span>
          </Spinner>
        </Async.Pending>
        <Async.Rejected>
          {e => <ErrorMessage error={e} />}
        </Async.Rejected>
        <Async.Fulfilled<AccountData>>{ad => <>
          <div className="mx-3 my-3">
            <WidgetWrapper title="My Account">
              <span>Manage your account data</span>
              <ManageUserData
                apiKey={props.apiKey}
                setApiKey={props.setApiKey}
                userData={ad.userData}
                ownEmail={ad.ownEmail}
                parentEmail={ad.parentEmail}
                setUserData={ud => setData(update(ad, { userData: { $set: ud } }))} />
            </WidgetWrapper>
          </div>
        </>}
        </Async.Fulfilled>
      </>}
    </Async>
  </SidebarLayout>
}

export default AccountWrapper;
