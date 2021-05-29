// Copyright (c) 2007, Clarius Consulting, Manas Technology Solutions, InSTEDD, and Contributors.
// All rights reserved. Licensed under the BSD 3-Clause License; see License.txt.

using System;
using System.ComponentModel;

using Moq.Language;
using Moq.Language.Flow;

namespace Moq.Protected
{
	/// <summary>
	/// Allows setups to be specified for protected members by using their 
	/// name as a string, rather than strong-typing them which is not possible 
	/// due to their visibility.
	/// </summary>
	[EditorBrowsable(EditorBrowsableState.Never)]
	public interface IProtectedMock<TMock> : IFluentInterface
		where TMock : class
	{
		/// <summary>
		/// Set up protected members (methods and properties) seen through another type with identical member signatures.
		/// </summary>
		/// <typeparam name="TAnalog">
		/// Any type with members whose signatures are identical to the mock's protected members (except for their accessibility level).
		/// </typeparam>
		IProtectedAsMock<TMock, TAnalog> As<TAnalog>()
			where TAnalog : class;

		#region Setup

		/// <summary>
		/// Specifies a setup for a void method invocation with the given 
		/// <paramref name="voidMethodName"/>, optionally specifying arguments for the method call.
		/// </summary>
		/// <param name="voidMethodName">The name of the void method to be invoked.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		ISetup<TMock> Setup(string voidMethodName, params object[] args);

		/// <summary>
		/// Specifies a setup for a void method invocation with the given
		/// <paramref name="voidMethodName"/>, optionally specifying arguments for the method call.
		/// </summary>
		/// <param name="voidMethodName">The name of the void method to be invoked.</param>
		/// <param name="exactParameterMatch">Should the parameter types match exactly types that were provided</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used,
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		ISetup<TMock> Setup(string voidMethodName, bool exactParameterMatch, params object[] args);

		/// <summary>
		/// Specifies a setup for a void method invocation with the given
		/// <paramref name="voidMethodName"/>, optionally specifying arguments for the method call.
		/// </summary>
		/// <param name="voidMethodName">The name of the void method to be invoked.</param>
		/// <param name="genericTypeArguments">An array of types to be substituted for the type parameters of the current generic method definition.</param>
		/// <param name="exactParameterMatch">Should the parameter types match exactly types that were provided</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used,
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		ISetup<TMock> Setup(string voidMethodName, Type[] genericTypeArguments, bool exactParameterMatch, params object[] args);

		/// <summary>
		/// Specifies a setup for an invocation on a property or a non void method with the given 
		/// <paramref name="methodOrPropertyName"/>, optionally specifying arguments for the method call.
		/// </summary>
		/// <param name="methodOrPropertyName">The name of the method or property to be invoked.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		/// <typeparam name="TResult">The return type of the method or property.</typeparam>
		ISetup<TMock, TResult> Setup<TResult>(string methodOrPropertyName, params object[] args);

		/// <summary>
		/// Specifies a setup for an invocation on a property or a non void method with the given 
		/// <paramref name="methodOrPropertyName"/>, optionally specifying arguments for the method call.
		/// </summary>
		/// <param name="methodOrPropertyName">The name of the method or property to be invoked.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		/// <param name="exactParameterMatch">Should the parameter types match exactly types that were provided</param>
		/// <typeparam name="TResult">The return type of the method or property.</typeparam>
		ISetup<TMock, TResult> Setup<TResult>(string methodOrPropertyName, bool exactParameterMatch, params object[] args);

		/// <summary>
		/// Specifies a setup for an invocation on a property or a non void method with the given 
		/// <paramref name="methodOrPropertyName"/>, optionally specifying arguments for the method call.
		/// </summary>
		/// <param name="methodOrPropertyName">The name of the method or property to be invoked.</param>
		/// <param name="genericTypeArguments">An array of types to be substituted for the type parameters of the current generic method definition.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		/// <param name="exactParameterMatch">Should the parameter types match exactly types that were provided</param>
		/// <typeparam name="TResult">The return type of the method or property.</typeparam>
		ISetup<TMock, TResult> Setup<TResult>(string methodOrPropertyName, Type[] genericTypeArguments, bool exactParameterMatch, params object[] args);

		/// <summary>
		/// Specifies a setup for an invocation on a property getter with the given 
		/// <paramref name="propertyName"/>.
		/// </summary>
		/// <param name="propertyName">The name of the property.</param>
		/// <typeparam name="TProperty">The type of the property.</typeparam>
		ISetupGetter<TMock, TProperty> SetupGet<TProperty>(string propertyName);

		/// <summary>
		/// Specifies a setup for an invocation on a property setter with the given 
		/// <paramref name="propertyName"/>.
		/// </summary>
		/// <param name="propertyName">The name of the property.</param>
		/// <param name="value">The property value. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		/// <typeparam name="TProperty">The type of the property.</typeparam>
		/// TODO should use value
		ISetupSetter<TMock, TProperty> SetupSet<TProperty>(string propertyName, object value);

		/// <summary>
		/// Specifies a setup for an invocation on a property setter with the given 
		/// <paramref name="propertyName"/>.
		/// </summary>
		/// <param name="propertyName">The name of the property.</param>
		/// <param name="value">The property value. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		ISetup<TMock> SetupSet(string propertyName, object value);

		/// <summary>
		/// Performs a sequence of actions, one per call.
		/// </summary>
		/// <param name="methodOrPropertyName">Name of the method or property being set up.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used,
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		ISetupSequentialAction SetupSequence(string methodOrPropertyName, params object[] args);

		/// <summary>
		/// Performs a sequence of actions, one per call.
		/// </summary>
		/// <param name="methodOrPropertyName">Name of the method or property being set up.</param>
		/// <param name="exactParameterMatch">Determines whether the parameter types should exactly match the types provided.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used,
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		ISetupSequentialAction SetupSequence(string methodOrPropertyName, bool exactParameterMatch, params object[] args);

		/// <summary>
		/// Performs a sequence of actions, one per call.
		/// </summary>
		/// <param name="methodOrPropertyName">Name of the method or property being set up.</param>
		/// <param name="genericTypeArguments">An array of types to be substituted for the type parameters of the current generic method definition.</param>
		/// <param name="exactParameterMatch">Determines whether the parameter types should exactly match the types provided.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used,
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		ISetupSequentialAction SetupSequence(string methodOrPropertyName, Type[] genericTypeArguments, bool exactParameterMatch, params object[] args);

		/// <summary>
		/// Return a sequence of values, once per call.
		/// </summary>
		/// <param name="methodOrPropertyName">Name of the method or property being set up.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used,
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		/// <typeparam name="TResult">Return type of the method or property being set up.</typeparam>
		ISetupSequentialResult<TResult> SetupSequence<TResult>(string methodOrPropertyName, params object[] args);

		/// <summary>
		/// Return a sequence of values, once per call.
		/// </summary>
		/// <param name="methodOrPropertyName">Name of the method or property being set up.</param>
		/// <param name="exactParameterMatch">Determines whether the parameter types should exactly match the types provided.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used,
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		/// <typeparam name="TResult">Return type of the method or property being set up.</typeparam>
		ISetupSequentialResult<TResult> SetupSequence<TResult>(string methodOrPropertyName, bool exactParameterMatch, params object[] args);

		/// <summary>
		/// Return a sequence of values, once per call.
		/// </summary>
		/// <param name="methodOrPropertyName">Name of the method or property being set up.</param>
		/// <param name="genericTypeArguments">An array of types to be substituted for the type parameters of the current generic method definition.</param>
		/// <param name="exactParameterMatch">Determines whether the parameter types should exactly match the types provided.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used,
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		/// <typeparam name="TResult">Return type of the method or property being set up.</typeparam>
		ISetupSequentialResult<TResult> SetupSequence<TResult>(string methodOrPropertyName, Type[] genericTypeArguments, bool exactParameterMatch, params object[] args);

		#endregion

		#region Verify

		/// <summary>
		/// Specifies a verify for a void method with the given <paramref name="methodName"/>,
		/// optionally specifying arguments for the method call. Use in conjunction with the default
		/// <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <exception cref="MockException">The invocation was not call the times specified by
		/// <paramref name="times"/>.</exception>
		/// <param name="methodName">The name of the void method to be verified.</param>
		/// <param name="times">The number of times a method is allowed to be called.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		void Verify(string methodName, Times times, params object[] args);

		/// <summary>
		/// Specifies a verify for a void method with the given <paramref name="methodName"/>,
		/// optionally specifying arguments for the method call. Use in conjunction with the default
		/// <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <exception cref="MockException">The invocation was not call the times specified by
		/// <paramref name="times"/>.</exception>
		/// <param name="methodName">The name of the void method to be verified.</param>
		/// <param name="genericTypeArguments">An array of types to be substituted for the type parameters of the current generic method definition.</param>
		/// <param name="times">The number of times a method is allowed to be called.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		void Verify(string methodName, Type[] genericTypeArguments, Times times, params object[] args);

		/// <summary>
		/// Specifies a verify for a void method with the given <paramref name="methodName"/>,
		/// optionally specifying arguments for the method call. Use in conjunction with the default
		/// <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <exception cref="MockException">The invocation was not call the times specified by
		/// <paramref name="times"/>.</exception>
		/// <param name="methodName">The name of the void method to be verified.</param>
		/// <param name="times">The number of times a method is allowed to be called.</param>
		/// <param name="exactParameterMatch">Should the parameter types match exactly types that were provided</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		void Verify(string methodName, Times times, bool exactParameterMatch, params object[] args);

		/// <summary>
		/// Specifies a verify for a void method with the given <paramref name="methodName"/>,
		/// optionally specifying arguments for the method call. Use in conjunction with the default
		/// <see cref="MockBehavior.Loose"/>.
		/// </summary>
		/// <exception cref="MockException">The invocation was not call the times specified by
		/// <paramref name="times"/>.</exception>
		/// <param name="methodName">The name of the void method to be verified.</param>
		/// <param name="genericTypeArguments">An array of types to be substituted for the type parameters of the current generic method definition.</param>
		/// <param name="times">The number of times a method is allowed to be called.</param>
		/// <param name="exactParameterMatch">Should the parameter types match exactly types that were provided</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		void Verify(string methodName, Type[] genericTypeArguments, Times times, bool exactParameterMatch, params object[] args);

		/// <summary>
		/// Specifies a verify for an invocation on a property or a non void method with the given 
		/// <paramref name="methodName"/>, optionally specifying arguments for the method call.
		/// </summary>
		/// <exception cref="MockException">The invocation was not call the times specified by 
		/// <paramref name="times"/>.</exception>
		/// <param name="methodName">The name of the method or property to be invoked.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		/// <param name="times">The number of times a method is allowed to be called.</param>
		/// <typeparam name="TResult">The type of return value from the expression.</typeparam>
		void Verify<TResult>(string methodName, Times times, params object[] args);

		/// <summary>
		/// Specifies a verify for an invocation on a property or a non void method with the given 
		/// <paramref name="methodName"/>, optionally specifying arguments for the method call.
		/// </summary>
		/// <exception cref="MockException">The invocation was not call the times specified by 
		/// <paramref name="times"/>.</exception>
		/// <param name="methodName">The name of the method or property to be invoked.</param>
		/// <param name="genericTypeArguments">An array of types to be substituted for the type parameters of the current generic method definition.</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		/// <param name="times">The number of times a method is allowed to be called.</param>
		/// <typeparam name="TResult">The type of return value from the expression.</typeparam>
		void Verify<TResult>(string methodName, Type[] genericTypeArguments, Times times, params object[] args);

		/// <summary>
		/// Specifies a verify for an invocation on a property or a non void method with the given 
		/// <paramref name="methodName"/>, optionally specifying arguments for the method call.
		/// </summary>
		/// <exception cref="MockException">The invocation was not call the times specified by 
		/// <paramref name="times"/>.</exception>
		/// <param name="methodName">The name of the method or property to be invoked.</param>
		/// <param name="exactParameterMatch">Should the parameter types match exactly types that were provided</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		/// <param name="times">The number of times a method is allowed to be called.</param>
		/// <typeparam name="TResult">The type of return value from the expression.</typeparam>
		void Verify<TResult>(string methodName, Times times, bool exactParameterMatch, params object[] args);

		/// <summary>
		/// Specifies a verify for an invocation on a property or a non void method with the given 
		/// <paramref name="methodName"/>, optionally specifying arguments for the method call.
		/// </summary>
		/// <exception cref="MockException">The invocation was not call the times specified by 
		/// <paramref name="times"/>.</exception>
		/// <param name="methodName">The name of the method or property to be invoked.</param>
		/// <param name="genericTypeArguments">An array of types to be substituted for the type parameters of the current generic method definition.</param>
		/// <param name="exactParameterMatch">Should the parameter types match exactly types that were provided</param>
		/// <param name="args">The optional arguments for the invocation. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</param>
		/// <param name="times">The number of times a method is allowed to be called.</param>
		/// <typeparam name="TResult">The type of return value from the expression.</typeparam>
		void Verify<TResult>(string methodName, Type[] genericTypeArguments, Times times, bool exactParameterMatch, params object[] args);

		/// <summary>
		/// Specifies a verify for an invocation on a property getter with the given 
		/// <paramref name="propertyName"/>.
		/// <exception cref="MockException">The invocation was not call the times specified by 
		/// <paramref name="times"/>.</exception>
		/// </summary>
		/// <param name="propertyName">The name of the property.</param>
		/// <param name="times">The number of times a method is allowed to be called.</param>
		/// <typeparam name="TProperty">The type of the property.</typeparam>
		// TODO should receive args to support indexers
		void VerifyGet<TProperty>(string propertyName, Times times);

		/// <summary>
		/// Specifies a setup for an invocation on a property setter with the given 
		/// <paramref name="propertyName"/>.
		/// </summary>
		/// <exception cref="MockException">The invocation was not call the times specified by 
		/// <paramref name="times"/>.</exception>
		/// <param name="propertyName">The name of the property.</param>
		/// <param name="times">The number of times a method is allowed to be called.</param>
		/// <param name="value">The property value.</param>
		/// <typeparam name="TProperty">The type of the property. If argument matchers are used, 
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>.</typeparam>
		// TODO should use value
		void VerifySet<TProperty>(string propertyName, Times times, object value);

		/// <summary>
		/// Specifies a setup for an invocation on a property setter with the given 
		/// <paramref name="propertyName"/>.
		/// </summary>
		/// <exception cref="MockException">The invocation was not call the times specified by 
		/// <paramref name="times"/>.</exception>
		/// <param name="propertyName">The name of the property.</param>
		/// <param name="times">The number of times a method is allowed to be called.</param>
		/// <param name="value">The property value.</param>
		/// remember to use <see cref="ItExpr"/> rather than <see cref="It"/>
		void VerifySet(string propertyName, Times times, object value);
		#endregion
	}
}
