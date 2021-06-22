// Copyright (c) 2007, Clarius Consulting, Manas Technology Solutions, InSTEDD, and Contributors.
// All rights reserved. Licensed under the BSD 3-Clause License; see License.txt.

using System;
using System.ComponentModel;
using System.Linq.Expressions;

using Moq.Language.Flow;

namespace Moq.Language
{
	/// <summary>
	/// Implements the fluent API.
	/// </summary>
	[EditorBrowsable(EditorBrowsableState.Never)]
	public interface ISetupConditionResultProtected<T, TAnalog> where T : class where TAnalog : class
	{
		/// <summary>
		/// The expectation will be considered only in the former condition.
		/// </summary>
		/// <param name="expression"></param>
		/// <returns></returns>
		ISetup<T> Setup(Expression<Action<TAnalog>> expression);

		/// <summary>
		/// The expectation will be considered only in the former condition.
		/// </summary>
		/// <typeparam name="TResult"></typeparam>
		/// <param name="expression"></param>
		/// <returns></returns>
		ISetup<T, TResult> Setup<TResult>(Expression<Func<TAnalog, TResult>> expression);

		/// <summary>
		/// Setups the get.
		/// </summary>
		/// <typeparam name="TProperty">The type of the property.</typeparam>
		/// <param name="expression">The expression.</param>
		/// <returns></returns>
		ISetupGetter<T, TProperty> SetupGet<TProperty>(Expression<Func<TAnalog, TProperty>> expression);

		/// <summary>
		/// Setups the set.
		/// </summary>
		/// <typeparam name="TProperty">The type of the property.</typeparam>
		/// <param name="setterExpression">The setter expression.</param>
		/// <returns></returns>
		ISetupSetter<T, TProperty> SetupSet<TProperty>(Action<TAnalog> setterExpression);

		/// <summary>
		/// Setups the set.
		/// </summary>
		/// <param name="setterExpression">The setter expression.</param>
		/// <returns></returns>
		ISetup<T> SetupSet(Action<TAnalog> setterExpression);
	}
}
