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

namespace chocolatey.infrastructure.app.services
{
    using System;
    using System.Collections.Concurrent;
    using configuration;
    using results;

    public interface INugetService : ISourceRunner
    {
        /// <summary>
        ///   Run pack in noop mode.
        /// </summary>
        /// <param name="config">The configuration.</param>
        void pack_noop(ChocolateyConfiguration config);

        /// <summary>
        ///   Packages up a nuspec into a compiled nupkg.
        /// </summary>
        /// <param name="config">The configuration.</param>
        void pack_run(ChocolateyConfiguration config);

        /// <summary>
        ///   Push_noops the specified configuration.
        /// </summary>
        /// <param name="config">The configuration.</param>
        void push_noop(ChocolateyConfiguration config);

        /// <summary>
        ///   Push_runs the specified configuration.
        /// </summary>
        /// <param name="config">The configuration.</param>
        void push_run(ChocolateyConfiguration config);
    }
}