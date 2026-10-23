import {
  forwardRef,
  useId,
  type ComponentPropsWithoutRef,
  type ReactNode,
} from 'react'
import clsx from 'clsx'

import { Icon, type IconName } from './icons'

/**
 * Form controls. Each field is a label above its control, with a description
 * or an error under it: the description says what the value does, the error
 * what is wrong and how to fix it. The `*Field` components wire label,
 * description and error to the control; the bare controls (`Input`, `Select`,
 * `Textarea`) are for a control labelled some other way (`aria-label` in a
 * table row).
 */

/** The ids a field's description and error get, for `aria-describedby`. */
function describedBy(id: string, description: ReactNode, error: ReactNode) {
  if (error) return `${id}-error`
  if (description) return `${id}-desc`
  return undefined
}

/** Description or error under a control (the error replaces the description). */
function FieldNote({
  id,
  description,
  error,
}: {
  id: string
  description?: ReactNode
  error?: ReactNode
}) {
  if (error) {
    return (
      <p id={`${id}-error`} className="fg-field-error">
        <Icon name="Alert" size={14} />
        <span>{error}</span>
      </p>
    )
  }
  if (description) {
    return (
      <p id={`${id}-desc`} className="fg-field-desc">
        {description}
      </p>
    )
  }
  return null
}

function FieldLabel({
  htmlFor,
  optional,
  children,
}: {
  htmlFor: string
  optional?: boolean
  children: ReactNode
}) {
  return (
    <label htmlFor={htmlFor} className="fg-label">
      {children}
      {optional && <span className="fg-optional">Optional</span>}
    </label>
  )
}

/** A bare text input with the design system's look. */
export const Input = forwardRef<
  HTMLInputElement,
  ComponentPropsWithoutRef<'input'> & { mono?: boolean; invalid?: boolean }
>(function Input({ mono, invalid, className, ...props }, ref) {
  return (
    <input
      ref={ref}
      {...props}
      aria-invalid={invalid ? true : props['aria-invalid']}
      className={clsx('fg-input', mono && 'fg-input--mono', invalid && 'fg-input--error', className)}
    />
  )
})

/** A bare multi-line input. */
export const Textarea = forwardRef<
  HTMLTextAreaElement,
  ComponentPropsWithoutRef<'textarea'> & { mono?: boolean; invalid?: boolean }
>(function Textarea({ mono, invalid, className, ...props }, ref) {
  return (
    <textarea
      ref={ref}
      {...props}
      aria-invalid={invalid ? true : props['aria-invalid']}
      className={clsx(
        'fg-textarea',
        mono && 'fg-input--mono',
        invalid && 'fg-input--error',
        className,
      )}
    />
  )
})

/** A bare native select with the chevron. Pass `<option>`s as children. */
export const Select = forwardRef<
  HTMLSelectElement,
  ComponentPropsWithoutRef<'select'> & { invalid?: boolean }
>(function Select({ invalid, className, ...props }, ref) {
  return (
    <div className={clsx('fg-select-wrap', className)}>
      <select
        ref={ref}
        {...props}
        aria-invalid={invalid ? true : props['aria-invalid']}
        className={clsx('fg-select', invalid && 'fg-select--error')}
      />
      <Icon name="ChevronDown" size={16} className="fg-select-chevron" />
    </div>
  )
})

interface FieldOwnProps {
  /** The noun the value is: "Remote URL". */
  label: ReactNode
  description?: ReactNode
  error?: ReactNode
  /** Marks the field "Optional" next to its label. */
  optional?: boolean
  className?: string
}

/** A labelled text input (URLs, ids, numbers in config units: `mono`). */
export const TextField = forwardRef<
  HTMLInputElement,
  FieldOwnProps & Omit<ComponentPropsWithoutRef<'input'>, 'className'> & { mono?: boolean }
>(function TextField(
  { label, description, error, optional, className, id, mono, ...input },
  ref,
) {
  const auto = useId()
  const inputId = id ?? auto
  return (
    <div className={clsx('fg-field', className)}>
      <FieldLabel htmlFor={inputId} optional={optional}>
        {label}
      </FieldLabel>
      <Input
        ref={ref}
        id={inputId}
        mono={mono}
        invalid={!!error}
        aria-describedby={describedBy(inputId, description, error)}
        {...input}
      />
      <FieldNote id={inputId} description={description} error={error} />
    </div>
  )
})

/** A labelled multi-line input. */
export const TextareaField = forwardRef<
  HTMLTextAreaElement,
  FieldOwnProps & Omit<ComponentPropsWithoutRef<'textarea'>, 'className'> & { mono?: boolean }
>(function TextareaField(
  { label, description, error, optional, className, id, mono, ...textarea },
  ref,
) {
  const auto = useId()
  const inputId = id ?? auto
  return (
    <div className={clsx('fg-field', className)}>
      <FieldLabel htmlFor={inputId} optional={optional}>
        {label}
      </FieldLabel>
      <Textarea
        ref={ref}
        id={inputId}
        mono={mono}
        invalid={!!error}
        aria-describedby={describedBy(inputId, description, error)}
        {...textarea}
      />
      <FieldNote id={inputId} description={description} error={error} />
    </div>
  )
})

/** A labelled native select. Pass `<option>`s as children. */
export const SelectField = forwardRef<
  HTMLSelectElement,
  FieldOwnProps & Omit<ComponentPropsWithoutRef<'select'>, 'className'>
>(function SelectField({ label, description, error, optional, className, id, ...select }, ref) {
  const auto = useId()
  const selectId = id ?? auto
  return (
    <div className={clsx('fg-field', className)}>
      <FieldLabel htmlFor={selectId} optional={optional}>
        {label}
      </FieldLabel>
      <Select
        ref={ref}
        id={selectId}
        invalid={!!error}
        aria-describedby={describedBy(selectId, description, error)}
        {...select}
      />
      <FieldNote id={selectId} description={description} error={error} />
    </div>
  )
})

interface ChoiceProps {
  label: ReactNode
  description?: ReactNode
  checked?: boolean
  defaultChecked?: boolean
  onChange?: (checked: boolean) => void
  disabled?: boolean
  /** Keep the label for assistive technology only (a switch in a table row). */
  hideLabel?: boolean
  id?: string
  name?: string
  value?: string
  required?: boolean
  className?: string
  'aria-label'?: string
}

function Choice({ kind, ...p }: ChoiceProps & { kind: 'checkbox' | 'switch' }) {
  const auto = useId()
  const id = p.id ?? auto
  // The label element holds the label alone, so the description is the
  // control's description (`aria-describedby`), not part of its name. The
  // invisible native input lies over the visual box, which takes the clicks.
  return (
    <div
      className={clsx(
        'fg-check',
        kind === 'switch' && 'fg-check--switch',
        p.disabled && 'is-disabled',
        p.className,
      )}
    >
      <input
        id={id}
        type="checkbox"
        role={kind === 'switch' ? 'switch' : undefined}
        className="fg-check-input"
        name={p.name}
        value={p.value}
        required={p.required}
        disabled={p.disabled}
        checked={p.checked}
        defaultChecked={p.defaultChecked}
        aria-label={p['aria-label']}
        onChange={p.onChange ? (e) => p.onChange?.(e.target.checked) : undefined}
        aria-describedby={p.description ? `${id}-desc` : undefined}
      />
      {kind === 'switch' ? (
        <span className="fg-switch-track" aria-hidden="true">
          <span className="fg-switch-thumb" />
        </span>
      ) : (
        <span className="fg-check-box" aria-hidden="true">
          <Icon name="Check" size={12} strokeWidth={2.25} />
        </span>
      )}
      <span className={clsx('fg-check-text', p.hideLabel && 'fg-sr')}>
        <label htmlFor={id} className="fg-check-label">
          {p.label}
        </label>
        {p.description && (
          <span id={`${id}-desc`} className="fg-field-desc">
            {p.description}
          </span>
        )}
      </span>
    </div>
  )
}

/** A check with a label: an option saved with a form, a filter applied at once. */
export function Checkbox(props: ChoiceProps) {
  return <Choice kind="checkbox" {...props} />
}

/**
 * On or off for a setting that stands alone (online, anonymous read, a realm
 * enabled). The label states the setting, never "Enable …".
 */
export function Switch(props: ChoiceProps) {
  return <Choice kind="switch" {...props} />
}

export interface RadioOption<T extends string> {
  value: T
  label: ReactNode
  description?: ReactNode
  disabled?: boolean
}

/**
 * Mutually exclusive options as a list of radios, under a legend. For a
 * decision that shapes everything after it, use `ChoiceCards`.
 */
export function RadioGroup<T extends string>({
  legend,
  description,
  name,
  value,
  onChange,
  options,
  disabled,
  className,
}: {
  legend?: ReactNode
  description?: ReactNode
  name?: string
  value: T
  onChange: (value: T) => void
  options: RadioOption<T>[]
  disabled?: boolean
  className?: string
}) {
  const auto = useId()
  const group = name ?? auto
  return (
    <fieldset className={clsx('fg-fieldset', className)} disabled={disabled}>
      {legend && <legend>{legend}</legend>}
      {description && <p className="fg-field-desc">{description}</p>}
      <div className="fg-choice-list">
        {options.map((o) => {
          const id = `${group}-${o.value}`
          return (
            <div
              key={o.value}
              className={clsx('fg-check fg-check--radio', o.disabled && 'is-disabled')}
            >
              <input
                id={id}
                type="radio"
                className="fg-check-input"
                name={group}
                value={o.value}
                checked={value === o.value}
                disabled={o.disabled}
                onChange={() => onChange(o.value)}
                aria-describedby={o.description ? `${id}-desc` : undefined}
              />
              <span className="fg-check-box" aria-hidden="true">
                <span className="fg-radio-dot" />
              </span>
              <span className="fg-check-text">
                <label htmlFor={id} className="fg-check-label">
                  {o.label}
                </label>
                {o.description && (
                  <span id={`${id}-desc`} className="fg-field-desc">
                    {o.description}
                  </span>
                )}
              </span>
            </div>
          )
        })}
      </div>
    </fieldset>
  )
}

/** A group of checkboxes (or other controls) under a legend. */
export function Fieldset({
  legend,
  description,
  children,
  className,
}: {
  legend: ReactNode
  description?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <fieldset className={clsx('fg-fieldset', className)}>
      <legend>{legend}</legend>
      {description && <p className="fg-field-desc">{description}</p>}
      {children}
    </fieldset>
  )
}

/** A search input with the search icon and an optional key hint. */
export function SearchField({
  label = 'Search',
  placeholder = 'Search…',
  value,
  onChange,
  shortcut,
  id,
  className,
}: {
  label?: string
  placeholder?: string
  value: string
  onChange: (value: string) => void
  shortcut?: string
  id?: string
  className?: string
}) {
  return (
    <div className={clsx('fg-search', className)} role="search">
      <Icon name="Search" size={16} />
      <input
        id={id}
        type="search"
        className="fg-input fg-search-input"
        aria-label={label}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {shortcut && <kbd className="fg-kbd">{shortcut}</kbd>}
    </div>
  )
}

export interface ChoiceCard<T extends string> {
  id: T
  title: string
  description?: ReactNode
  icon?: IconName
  disabled?: boolean
}

/**
 * Radio choices as cards, for a decision that shapes everything after it: the
 * kind of a new repository, its format. Two to four options, each with a
 * one-sentence description.
 */
export function ChoiceCards<T extends string>({
  label,
  description,
  options,
  value,
  onChange,
  name,
  className,
}: {
  label?: ReactNode
  description?: ReactNode
  options: ChoiceCard<T>[]
  value: T
  onChange: (id: T) => void
  name?: string
  className?: string
}) {
  const auto = useId()
  const group = name ?? auto
  return (
    <div
      className={clsx('fg-choices', className)}
      role="radiogroup"
      aria-labelledby={label ? `${auto}-label` : undefined}
    >
      {label && (
        <div id={`${auto}-label`} className="fg-label">
          {label}
        </div>
      )}
      <div className="fg-choices-grid">
        {options.map((o) => {
          const on = o.id === value
          return (
            <label
              key={o.id}
              className={clsx('fg-choice', on && 'is-selected', o.disabled && 'is-disabled')}
            >
              <input
                type="radio"
                className="fg-choice-input"
                name={group}
                value={o.id}
                checked={on}
                disabled={o.disabled}
                onChange={() => onChange(o.id)}
                aria-describedby={o.description ? `${group}-${o.id}-desc` : undefined}
              />
              <span className="fg-choice-top">
                {o.icon && (
                  <span className="fg-choice-icon">
                    <Icon name={o.icon} size={18} />
                  </span>
                )}
                <span className="fg-choice-title">{o.title}</span>
                <span className="fg-choice-check" aria-hidden="true">
                  <Icon name="Check" size={12} strokeWidth={2.25} />
                </span>
              </span>
              {o.description && (
                <span id={`${group}-${o.id}-desc`} className="fg-choice-desc">
                  {o.description}
                </span>
              )}
            </label>
          )
        })}
      </div>
      {description && <p className="fg-field-desc">{description}</p>}
    </div>
  )
}
