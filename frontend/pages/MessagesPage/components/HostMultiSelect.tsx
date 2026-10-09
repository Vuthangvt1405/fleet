import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import Select, {
  components,
  InputActionMeta,
  MultiValue,
  OptionProps,
  StylesConfig,
} from "react-select-5";

import {
  generateCustomDropdownStyles,
  CustomOptionType,
} from "components/forms/fields/DropdownWrapper/DropdownWrapper";
import FormField from "components/forms/FormField";
import { IHost } from "interfaces/host";
import hostsAPI from "services/entities/hosts";
import debounce from "utilities/debounce";

const baseClass = "host-multi-select";
const HOST_SEARCH_DEBOUNCE_MS = 300;
const HOST_SEARCH_PAGE_SIZE = 20;

interface IHostSelectOption extends CustomOptionType {
  host: IHost;
}

interface IHostMultiSelectProps {
  selectedHosts: IHost[];
  onChange: (hosts: IHost[]) => void;
}

const toOption = (host: IHost): IHostSelectOption => ({
  value: String(host.id),
  label: host.hostname,
  host,
});

const HostOption = (props: OptionProps<IHostSelectOption, true>) => {
  const { data } = props;
  return (
    <components.Option {...props}>
      <div className={`${baseClass}__option`}>
        <span className={`${baseClass}__hostname`}>{data.label}</span>
        <span className={`${baseClass}__help-text`}>{data.host.platform}</span>
      </div>
    </components.Option>
  );
};

/** Search and select hosts by hostname. Selected hosts are displayed as chips. */
const HostMultiSelect = ({
  selectedHosts,
  onChange,
}: IHostMultiSelectProps): JSX.Element => {
  const [options, setOptions] = useState<IHostSelectOption[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const requestID = useRef(0);

  const searchHosts = useCallback(async (query: string) => {
    requestID.current += 1;
    const currentRequestID = requestID.current;
    setIsLoading(true);
    try {
      const { hosts } = await hostsAPI.loadHosts({
        globalFilter: query || undefined,
        perPage: HOST_SEARCH_PAGE_SIZE,
      });
      if (currentRequestID === requestID.current) {
        setOptions(hosts.map(toOption));
      }
    } catch {
      // Keep current results on failure; a later search can retry.
    } finally {
      if (currentRequestID === requestID.current) {
        setIsLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    searchHosts("");
  }, [searchHosts]);

  const debouncedSearch = useMemo(
    () =>
      debounce(searchHosts, {
        timeout: HOST_SEARCH_DEBOUNCE_MS,
        leading: false,
        trailing: true,
      }),
    [searchHosts]
  );

  const onInputChange = (newValue: string, { action }: InputActionMeta) => {
    if (action === "input-change") {
      debouncedSearch(newValue);
    }
    return newValue;
  };

  const onSelectChange = (selected: MultiValue<IHostSelectOption>) => {
    onChange(selected.map((option) => option.host));
  };

  return (
    <div className={baseClass}>
      <FormField
        name="message-hosts"
        label="Hosts"
        type="dropdown"
        className={`${baseClass}__field`}
      >
        <Select<IHostSelectOption, true>
          aria-label="Select hosts"
          classNamePrefix="react-select"
          isMulti
          isSearchable
          isLoading={isLoading}
          styles={
            (generateCustomDropdownStyles() as unknown) as StylesConfig<
              IHostSelectOption,
              true
            >
          }
          options={options}
          value={selectedHosts.map(toOption)}
          components={{ Option: HostOption }}
          onInputChange={onInputChange}
          onChange={onSelectChange}
          filterOption={() => true}
          placeholder="Search hosts by name…"
          noOptionsMessage={({ inputValue }) =>
            inputValue ? "No hosts found" : "No hosts available"
          }
        />
      </FormField>
    </div>
  );
};

export default HostMultiSelect;
