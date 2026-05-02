import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect } from 'vitest';

/**
 * Helper functions for testing forms
 */

export const formHelpers = {
    /**
     * Fill a text input field
     */
    async fillInput(labelText: string, value: string) {
        const input = screen.getByLabelText(labelText);
        await userEvent.clear(input);
        await userEvent.type(input, value);
        return input;
    },

    /**
     * Fill an input by placeholder text
     */
    async fillInputByPlaceholder(placeholderText: string, value: string) {
        const input = screen.getByPlaceholderText(placeholderText);
        await userEvent.clear(input);
        await userEvent.type(input, value);
        return input;
    },

    /**
     * Select an option from a select dropdown
     */
    async selectOption(labelText: string, optionText: string) {
        const select = screen.getByLabelText(labelText);
        await userEvent.selectOptions(select, optionText);
        return select;
    },

    /**
     * Click a checkbox
     */
    async toggleCheckbox(labelText: string) {
        const checkbox = screen.getByLabelText(labelText);
        await userEvent.click(checkbox);
        return checkbox;
    },

    /**
     * Click a radio button
     */
    async selectRadio(labelText: string) {
        const radio = screen.getByLabelText(labelText);
        await userEvent.click(radio);
        return radio;
    },

    /**
     * Submit a form
     */
    async submitForm(buttonText = 'Submit') {
        const submitButton = screen.getByRole('button', { name: buttonText });
        await userEvent.click(submitButton);
        return submitButton;
    },

    /**
     * Wait for form validation errors to appear
     */
    async waitForValidationError(errorText: string) {
        return await waitFor(() => screen.getByText(errorText));
    },

    /**
     * Check if a field has an error
     */
    expectFieldError(labelText: string, errorText: string) {
        const field = screen.getByLabelText(labelText);
        expect(field).toHaveAttribute('aria-invalid', 'true');
        expect(screen.getByText(errorText)).toBeInTheDocument();
    },

    /**
     * Check if a field is valid
     */
    expectFieldValid(labelText: string) {
        const field = screen.getByLabelText(labelText);
        expect(field).not.toHaveAttribute('aria-invalid', 'true');
    },

    /**
     * Fill out a complete login form
     */
    async fillLoginForm(email: string, password: string, rememberMe = false) {
        await this.fillInput('Email', email);
        await this.fillInput('Password', password);

        if (rememberMe) {
            await this.toggleCheckbox('Remember me');
        }
    },

    /**
     * Fill out a secret creation form
     */
    async fillSecretForm(secretData: {
        name: string;
        value: string;
        type?: string;
        namespace?: string;
        zone?: string;
        environment?: string;
        description?: string;
    }) {
        await this.fillInput('Name', secretData.name);
        await this.fillInput('Value', secretData.value);

        if (secretData.type) {
            await this.selectOption('Type', secretData.type);
        }

        if (secretData.namespace) {
            await this.fillInput('Namespace', secretData.namespace);
        }

        if (secretData.zone) {
            await this.fillInput('Zone', secretData.zone);
        }

        if (secretData.environment) {
            await this.fillInput('Environment', secretData.environment);
        }

        if (secretData.description) {
            await this.fillInput('Description', secretData.description);
        }
    },
};

/**
 * Helper for testing async form submissions
 */
export const asyncFormHelpers = {
    /**
     * Submit form and wait for success message
     */
    async submitAndWaitForSuccess(buttonText = 'Submit', successText = 'Success') {
        await formHelpers.submitForm(buttonText);
        return await waitFor(() => screen.getByText(successText));
    },

    /**
     * Submit form and wait for error message
     */
    async submitAndWaitForError(buttonText = 'Submit', errorText: string) {
        await formHelpers.submitForm(buttonText);
        return await waitFor(() => screen.getByText(errorText));
    },

    /**
     * Submit form and wait for loading state
     */
    async submitAndWaitForLoading(buttonText = 'Submit') {
        await formHelpers.submitForm(buttonText);
        return await waitFor(() => screen.getByText('Loading...'));
    },
};

/**
 * Helper for testing form accessibility
 */
export const accessibilityHelpers = {
    /**
     * Check if form has proper labels
     */
    expectProperLabels(fieldNames: string[]) {
        fieldNames.forEach(fieldName => {
            const field = screen.getByLabelText(fieldName);
            expect(field).toBeInTheDocument();
            expect(field).toHaveAccessibleName(fieldName);
        });
    },

    /**
     * Check if form has proper ARIA attributes
     */
    expectProperAria(labelText: string) {
        const field = screen.getByLabelText(labelText);
        expect(field).toHaveAttribute('aria-describedby');
    },

    /**
     * Check if error messages are properly associated
     */
    expectErrorAssociation(labelText: string, errorText: string) {
        const field = screen.getByLabelText(labelText);
        const errorElement = screen.getByText(errorText);

        expect(field).toHaveAttribute('aria-invalid', 'true');
        expect(field).toHaveAttribute('aria-describedby');
        expect(errorElement).toHaveAttribute('role', 'alert');
    },
};