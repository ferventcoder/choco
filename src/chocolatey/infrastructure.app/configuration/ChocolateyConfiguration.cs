﻿// Copyright © 2011 - Present RealDimensions Software, LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// 
// You may obtain a copy of the License at
// 
// 	http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

namespace chocolatey.infrastructure.app.configuration
{
    using System;
    using System.Collections.Generic;
    using System.Reflection;
    using System.Text;
    using domain;
    using logging;
    using platforms;

    /// <summary>
    ///   The chocolatey configuration.
    /// </summary>
    [Serializable]
    public class ChocolateyConfiguration
    {
        public ChocolateyConfiguration()
        {
            RegularOuptut = true;
            PromptForConfirmation = true;
            SourceType = SourceType.normal;
            Information = new InformationCommandConfiguration();
            Features = new FeaturesConfiguration();
            NewCommand = new NewCommandConfiguration();
            ListCommand = new ListCommandConfiguration();
            UpgradeCommand = new UpgradeCommandConfiguration();
            SourceCommand = new SourcesCommandConfiguration();
            FeatureCommand = new FeatureCommandConfiguration();
            ApiKeyCommand = new ApiKeyCommandConfiguration();
            PushCommand = new PushCommandConfiguration();
            PinCommand = new PinCommandConfiguration();
#if DEBUG
            AllowUnofficialBuild = true;
#endif
        }

        // overrides
        public override string ToString()
        {
            var properties = new StringBuilder();

            this.Log().Debug(ChocolateyLoggers.Important,@"
NOTE: Hiding sensitive configuration data! Please double and triple 
 check to be sure no sensitive data is shown, especially if copying 
 output to a gist for review.");
            output_tostring(properties, GetType().GetProperties(), this, "");
            return properties.ToString();

        }

        private void output_tostring(StringBuilder propertyValues, IEnumerable<PropertyInfo> properties, object obj, string prepend)
        {
            foreach (var propertyInfo in properties.or_empty_list_if_null())
            {
                // skip sensitive data info
                if (propertyInfo.Name == "Password" || propertyInfo.Name == "Key")
                {
                    continue;
                }

                var objectValue = propertyInfo.GetValue(obj, null);
                if (propertyInfo.PropertyType.is_built_in_system_type())
                {
                    if (!string.IsNullOrWhiteSpace(objectValue.to_string()))
                    {
                        var output = "{0}{1}='{2}'|".format_with(
                            string.IsNullOrWhiteSpace(prepend) ? "" : prepend + ".",
                            propertyInfo.Name,
                            objectValue.to_string());

                        append_output(propertyValues, output);
                    }
                }
                else if (propertyInfo.PropertyType.is_collections_type())
                {
                    var list = objectValue as IDictionary<string, string>;
                    foreach (var item in list.or_empty_list_if_null())
                    {
                        var output = "{0}{1}.{2}='{3}'|".format_with(
                            string.IsNullOrWhiteSpace(prepend) ? "" : prepend + ".",
                            propertyInfo.Name,
                            item.Key,
                            item.Value);

                        append_output(propertyValues, output);
                    }
                }
                else
                {
                    output_tostring(propertyValues, propertyInfo.PropertyType.GetProperties(), objectValue, propertyInfo.Name);
                }
            }
        }

        private const int MAX_CONSOLE_LINE_LENGTH = 72;
        private int _currentLineLength = 0;

        private void append_output(StringBuilder propertyValues, string append)
        {
            _currentLineLength += append.Length;

            propertyValues.AppendFormat("{0}{1}{2}",
                   _currentLineLength < MAX_CONSOLE_LINE_LENGTH ? string.Empty : Environment.NewLine,
                   append,
                   append.Length < MAX_CONSOLE_LINE_LENGTH ? string.Empty : Environment.NewLine);

            if (_currentLineLength > MAX_CONSOLE_LINE_LENGTH)
            {
                _currentLineLength = append.Length;
            }
        }

        /// <summary>
        ///   Gets or sets the name of the command.
        ///   This is the command that choco runs.
        /// </summary>
        /// <value>
        ///   The name of the command.
        /// </value>
        public string CommandName { get; set; }

        // configuration set variables
        public string CacheLocation { get; set; }
        public bool ContainsLegacyPackageInstalls { get; set; }
        public int CommandExecutionTimeoutSeconds { get; set; }

        /// <summary>
        ///   One or more source locations set by configuration or by command line. Separated by semi-colon
        /// </summary>
        public string Sources { get; set; }
        public SourceType SourceType { get; set; }

        // top level commands

        public bool Debug { get; set; }
        public bool Verbose { get; set; }
        public bool Force { get; set; }
        public bool Noop { get; set; }
        public bool HelpRequested { get; set; }
        public bool RegularOuptut { get; set; }
        public bool PromptForConfirmation { get; set; }
        public bool AcceptLicense { get; set; }
        public bool AllowUnofficialBuild { get; set; }


        /// <summary>
        ///   Usually related to unparsed arguments.
        /// </summary>
        public string Input { get; set; }

        // command level options
        public string Version { get; set; }
        public bool AllVersions { get; set; }
        public bool SkipPackageInstallProvider { get; set; }

        // install/update
        /// <summary>
        ///   Gets or sets the package names. Space separated
        /// </summary>
        /// <value>
        ///   Space separated package names.
        /// </value>
        public string PackageNames { get; set; }

        public bool Prerelease { get; set; }
        public bool ForceX86 { get; set; }
        public string InstallArguments { get; set; }
        public bool OverrideArguments { get; set; }
        public bool NotSilent { get; set; }
        public string PackageParameters { get; set; }
        public bool IgnoreDependencies { get; set; }
        public bool AllowMultipleVersions { get; set; }
        public bool ForceDependencies { get; set; }

        /// <summary>
        ///   Configuration values provided by choco.
        /// </summary>
        public InformationCommandConfiguration Information { get; private set; }

        /// <summary>
        ///   Configuration related to features and whether they are enabled.
        /// </summary>
        public FeaturesConfiguration Features { get; private set; }

        /// <summary>
        ///   Configuration related specifically to List command
        /// </summary>
        public ListCommandConfiguration ListCommand { get; private set; }

        /// <summary>
        ///   Configuration related specifically to Upgrade command
        /// </summary>
        public UpgradeCommandConfiguration UpgradeCommand { get; private set; }

        /// <summary>
        ///   Configuration related specifically to New command
        /// </summary>
        public NewCommandConfiguration NewCommand { get; private set; }

        /// <summary>
        ///   Configuration related specifically to Source command
        /// </summary>
        public SourcesCommandConfiguration SourceCommand { get; private set; }

        /// <summary>
        /// Configuration related specifically to the Feature command
        /// </summary>
        public FeatureCommandConfiguration FeatureCommand { get; private set; }

        /// <summary>
        ///   Configuration related specifically to ApiKey command
        /// </summary>
        public ApiKeyCommandConfiguration ApiKeyCommand { get; private set; }

        /// <summary>
        ///   Configuration related specifically to Push command
        /// </summary>
        public PushCommandConfiguration PushCommand { get; private set; }

        /// <summary>
        /// Configuration related specifically to Pin command
        /// </summary>
        public PinCommandConfiguration PinCommand { get; private set; }
    }

    [Serializable]
    public sealed class InformationCommandConfiguration
    {
        // application set variables
        public PlatformType PlatformType { get; set; }
        public Version PlatformVersion { get; set; }
        public string ChocolateyVersion { get; set; }
        public string ChocolateyProductVersion { get; set; }
        public string FullName { get; set; }
        public bool Is64Bit { get; set; }
        public bool IsInteractive { get; set; }
    }

    [Serializable]
    public sealed class FeaturesConfiguration
    {
        public bool AutoUninstaller { get; set; }
        public bool CheckSumFiles { get; set; }
    }

    //todo: retrofit other command configs this way

    [Serializable]
    public sealed class ListCommandConfiguration
    {
        // list
        public bool LocalOnly { get; set; }
        public bool IncludeRegistryPrograms { get; set; }
    }  
    
    [Serializable]
    public sealed class UpgradeCommandConfiguration
    {
        public bool FailOnUnfound { get; set; }
    }

    [Serializable]
    public sealed class NewCommandConfiguration
    {
        public NewCommandConfiguration()
        {
            TemplateProperties = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);
        }

        public string Name { get; set; }
        public bool AutomaticPackage { get; set; }
        public IDictionary<string, string> TemplateProperties { get; private set; }
    }

    [Serializable]
    public sealed class SourcesCommandConfiguration
    {
        public string Name { get; set; }
        public SourceCommandType Command { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    [Serializable]
    public sealed class FeatureCommandConfiguration
    {
        public string Name { get; set; }
        public FeatureCommandType Command { get; set; }
    }

    [Serializable]
    public sealed class PinCommandConfiguration
    {
        public string Name { get; set; }
        public PinCommandType Command { get; set; }
    }

    [Serializable]
    public sealed class ApiKeyCommandConfiguration
    {
        public string Key { get; set; }
    }

    [Serializable]
    public sealed class PushCommandConfiguration
    {
        public string Key { get; set; }
        public int TimeoutInSeconds { get; set; }
        //DisableBuffering?
    }
}