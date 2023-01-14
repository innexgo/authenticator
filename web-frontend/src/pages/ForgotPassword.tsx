import React from 'react';
import { Formik, FormikHelpers } from 'formik'
import { Button, Card, Form, } from 'react-bootstrap'
import { passwordResetNew } from '@innexgo/frontend-auth-api';
import { isErr } from '@innexgo/frontend-common';
import { BrandedComponentProps } from '@innexgo/common-react-components';
import SidebarLayout from '../components/SidebarLayout';


type ForgotPasswordFormProps = {
  onSuccess: () => void;
}

function ForgotPasswordForm(props: ForgotPasswordFormProps) {

  type ForgotPasswordValue = {
    email: string,
  }

  const onSubmit = async (values: ForgotPasswordValue, { setErrors, setStatus }: FormikHelpers<ForgotPasswordValue>) => {
    // Validate input
    if (values.email === "") {
      setErrors({ email: "Please enter your email" });
      return;
    }

    // Now send request
    const maybePasswordResetKey = await passwordResetNew({
      email: values.email
    });

    if (isErr(maybePasswordResetKey)) {
      switch (maybePasswordResetKey.Err) {
        case "USER_NONEXISTENT": {
          setErrors({ email: "No such user exists." });
          break;
        }
        case "EMAIL_BOUNCED": {
          setErrors({ email: "This email address is invalid." });
          break;
        }
        case "EMAIL_COOLDOWN": {
          setStatus("Please wait 15 minutes before trying to send more emails.");
          break;
        }
        default: {
          setStatus("An unknown or network error has occured while trying to reset the password.");
          break;
        }
      }
      return;
    }

    props.onSuccess();
  }

  return (
    <Formik
      onSubmit={onSubmit}
      initialValues={{
        email: "",
      }}
      initialStatus=""
    >
      {(props) => (
        <Form
          noValidate
          onSubmit={props.handleSubmit} >
          <Form.Group className="mb-3">
            <Form.Label>Email</Form.Label>
            <Form.Control
              name="email"
              type="email"
              placeholder="Email"
              value={props.values.email}
              onChange={props.handleChange}
              isInvalid={!!props.errors.email}
            />
            <Form.Control.Feedback type="invalid"> {props.errors.email} </Form.Control.Feedback>
          </Form.Group>
          <Form.Group className="mb-3">
            <Button type="submit">Submit</Button>
          </Form.Group>
          <Form.Group className="mb-3">
            <Form.Text className="text-danger">{props.status}</Form.Text>
          </Form.Group>
        </Form>
      )}
    </Formik>
  )
}

function ForgotPassword(props: BrandedComponentProps) {
  const [successful, setSuccess] = React.useState(false);
  return <SidebarLayout branding={props.branding}>
    <div className="h-100 w-100 d-flex">
      <Card className="mx-auto my-auto col-md-6">
        <Card.Body>
          <Card.Title>Send Reset Password Email</Card.Title>
          {successful
            ? <Form.Text className="text-success">We've sent an email to reset your password.</Form.Text>
            : <ForgotPasswordForm onSuccess={() => setSuccess(true)} />
          }
        </Card.Body>
      </Card>
    </div>
  </SidebarLayout>
}

export default ForgotPassword;
