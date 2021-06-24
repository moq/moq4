// Copyright (c) 2007, Clarius Consulting, Manas Technology Solutions, InSTEDD, and Contributors.
// All rights reserved. Licensed under the BSD 3-Clause License; see License.txt.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;

using Moq.Language;
using Moq.Language.Flow;
using Moq.Properties;

namespace Moq.Protected
{
	internal sealed class ProtectedAsMock<T, TAnalog> : IProtectedAsMock<T, TAnalog>
		where T : class
		where TAnalog : class
	{
		private Mock<T> mock;
		private IndexerSetup indexerSetup;

		private static DuckReplacer DuckReplacerInstance = new DuckReplacer(typeof(TAnalog), typeof(T));

		public ProtectedAsMock(Mock<T> mock)
		{
			Debug.Assert(mock != null);
			this.indexerSetup = new IndexerSetup(mock);

			this.mock = mock;
		}

		public ISetup<T> Setup(Expression<Action<TAnalog>> expression)
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Action<T>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Action<T>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			var setup = Mock.Setup(this.mock, rewrittenExpression, null);
			return new VoidSetupPhrase<T>(setup);
		}

		public ISetup<T, TResult> Setup<TResult>(Expression<Func<TAnalog, TResult>> expression)
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Func<T, TResult>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Func<T, TResult>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			var setup = Mock.Setup(this.mock, rewrittenExpression, null);
			return new NonVoidSetupPhrase<T, TResult>(setup);
		}

		public ISetupGetter<T, TProperty> SetupGet<TProperty>(Expression<Func<TAnalog, TProperty>> expression)
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Func<T, TProperty>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Func<T, TProperty>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			var setup = Mock.SetupGet(this.mock, rewrittenExpression, null);
			return new NonVoidSetupPhrase<T, TProperty>(setup);
		}

		public Mock<T> SetupProperty<TProperty>(Expression<Func<TAnalog, TProperty>> expression, TProperty initialValue = default(TProperty))
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Func<T, TProperty>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Func<T, TProperty>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			return this.mock.SetupProperty<TProperty>(rewrittenExpression, initialValue);
		}

		public Mock<T> SetupIndexer<TProperty>(Expression<Func<TAnalog, TProperty>> expression, TProperty initialValue = default(TProperty))
		{
			Guard.NotNull(expression, nameof(expression));
			indexerSetup.Setup(expression, initialValue, nameof(expression), ReplaceDuck);

			return this.mock;
		}

		public ISetupSequentialResult<TResult> SetupSequence<TResult>(Expression<Func<TAnalog, TResult>> expression)
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Func<T, TResult>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Func<T, TResult>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			var setup = Mock.SetupSequence(this.mock, rewrittenExpression);
			return new SetupSequencePhrase<TResult>(setup);
		}

		public ISetupSequentialAction SetupSequence(Expression<Action<TAnalog>> expression)
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Action<T>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Action<T>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			var setup = Mock.SetupSequence(this.mock, rewrittenExpression);
			return new SetupSequencePhrase(setup);
		}

		public void Verify(Expression<Action<TAnalog>> expression, Times? times = null, string failMessage = null)
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Action<T>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Action<T>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			Mock.Verify(this.mock, rewrittenExpression, times ?? Times.AtLeastOnce(), failMessage);
		}

		public void Verify<TResult>(Expression<Func<TAnalog, TResult>> expression, Times? times = null, string failMessage = null)
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Func<T, TResult>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Func<T, TResult>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			Mock.Verify(this.mock, rewrittenExpression, times ?? Times.AtLeastOnce(), failMessage);
		}

		public void VerifyGet<TProperty>(Expression<Func<TAnalog, TProperty>> expression, Times? times = null, string failMessage = null)
		{
			Guard.NotNull(expression, nameof(expression));

			Expression<Func<T, TProperty>> rewrittenExpression;
			try
			{
				rewrittenExpression = (Expression<Func<T, TProperty>>)ReplaceDuck(expression);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException(ex.Message, nameof(expression));
			}

			Mock.VerifyGet(this.mock, rewrittenExpression, times ?? Times.AtLeastOnce(), failMessage);
		}

		private static LambdaExpression ReplaceDuck(LambdaExpression expression)
		{
			Debug.Assert(expression.Parameters.Count == 1);

			var targetParameter = Expression.Parameter(typeof(T), expression.Parameters[0].Name);
			return Expression.Lambda(DuckReplacerInstance.Visit(expression.Body), targetParameter);
		}

		/// <summary>
		/// <see cref="ExpressionVisitor"/> used to replace occurrences of `TAnalog.Member` sub-expressions with `T.Member`.
		/// </summary>
		private sealed class DuckReplacer : ExpressionVisitor
		{
			private Type duckType;
			private Type targetType;

			public DuckReplacer(Type duckType, Type targetType)
			{
				this.duckType = duckType;
				this.targetType = targetType;
			}

			protected override Expression VisitMethodCall(MethodCallExpression node)
			{
				if (node.Object is ParameterExpression left && left.Type == this.duckType)
				{
					var targetParameter = Expression.Parameter(this.targetType, left.Name);
					return Expression.Call(targetParameter, FindCorrespondingMethod(node.Method), node.Arguments);
				}
				else
				{
					return node;
				}
			}

			protected override Expression VisitMember(MemberExpression node)
			{
				if (node.Expression is ParameterExpression left && left.Type == this.duckType)
				{
					var targetParameter = Expression.Parameter(this.targetType, left.Name);
					return Expression.MakeMemberAccess(targetParameter, FindCorrespondingMember(node.Member));
				}
				else
				{
					return node;
				}
			}

			private MemberInfo FindCorrespondingMember(MemberInfo duckMember)
			{
				if (duckMember is MethodInfo duckMethod)
				{
					return FindCorrespondingMethod(duckMethod);
				}
				else if (duckMember is PropertyInfo duckProperty)
				{
					return FindCorrespondingProperty(duckProperty);
				}
				else
				{
					throw new NotSupportedException();
				}
			}

			private MethodInfo FindCorrespondingMethod(MethodInfo duckMethod)
			{
				var candidateTargetMethods =
				    this.targetType
				    .GetMethods(BindingFlags.NonPublic | BindingFlags.Instance)
				    .Where(ctm => IsCorrespondingMethod(duckMethod, ctm))
				    .ToArray();

				if (candidateTargetMethods.Length == 0)
				{
					throw new ArgumentException(string.Format(Resources.ProtectedMemberNotFound, this.targetType, duckMethod));
				}

				Debug.Assert(candidateTargetMethods.Length == 1);

				var targetMethod = candidateTargetMethods[0];

				if (targetMethod.IsGenericMethodDefinition)
				{
					var duckGenericArgs = duckMethod.GetGenericArguments();
					targetMethod = targetMethod.MakeGenericMethod(duckGenericArgs);
				}

				return targetMethod;
			}

			private PropertyInfo FindCorrespondingProperty(PropertyInfo duckProperty)
			{
				var candidateTargetProperties =
				    this.targetType
				    .GetProperties(BindingFlags.NonPublic | BindingFlags.Instance)
				    .Where(ctp => IsCorrespondingProperty(duckProperty, ctp))
				    .ToArray();

				if (candidateTargetProperties.Length == 0)
				{
					throw new ArgumentException(string.Format(Resources.ProtectedMemberNotFound, this.targetType, duckProperty));
				}

				Debug.Assert(candidateTargetProperties.Length == 1);

				return candidateTargetProperties[0];
			}

			private static bool IsCorrespondingMethod(MethodInfo duckMethod, MethodInfo candidateTargetMethod)
			{
				if (candidateTargetMethod.Name != duckMethod.Name)
				{
					return false;
				}

				if (candidateTargetMethod.IsGenericMethod != duckMethod.IsGenericMethod)
				{
					return false;
				}

				if (candidateTargetMethod.IsGenericMethodDefinition)
				{
					// when both methods are generic, then the candidate method should be an open generic method
					// while the duck-type method should be a closed one. in this case, we close the former
					// over the same generic type arguments that the latter uses.

					Debug.Assert(!duckMethod.IsGenericMethodDefinition);

					var candidateGenericArgs = candidateTargetMethod.GetGenericArguments();
					var duckGenericArgs = duckMethod.GetGenericArguments();

					if (candidateGenericArgs.Length != duckGenericArgs.Length)
					{
						return false;
					}

					// this could perhaps go wrong due to generic type parameter constraints; if it does
					// go wrong, then obviously the duck-type method doesn't correspond to the candidate.
					try
					{
						candidateTargetMethod = candidateTargetMethod.MakeGenericMethod(duckGenericArgs);
					}
					catch
					{
						return false;
					}
				}

				var duckParameters = duckMethod.GetParameters();
				var candidateParameters = candidateTargetMethod.GetParameters();

				if (candidateParameters.Length != duckParameters.Length)
				{
					return false;
				}

				for (int i = 0, n = candidateParameters.Length; i < n; ++i)
				{
					if (candidateParameters[i].ParameterType != duckParameters[i].ParameterType)
					{
						return false;
					}
				}

				return true;
			}

			private static bool IsCorrespondingProperty(PropertyInfo duckProperty, PropertyInfo candidateTargetProperty)
			{
				return candidateTargetProperty.Name == duckProperty.Name
				    && candidateTargetProperty.PropertyType == duckProperty.PropertyType
				    && candidateTargetProperty.CanRead(out _) == duckProperty.CanRead(out _)
				    && candidateTargetProperty.CanWrite(out _) == duckProperty.CanWrite(out _);

				// TODO: parameter lists should be compared, too, to properly support indexers.
			}
		}
		private class IndexerSetup
		{
			private readonly Mock<T> mock;

			private static MethodInfo itIsAnyMethod;
			static IndexerSetup()
			{
				itIsAnyMethod = typeof(It).GetMethod("IsAny");
			}
			public IndexerSetup(Mock<T> mock)
			{
				this.mock = mock;
			}

			private MethodCallExpression GetGetter<TProperty>(Expression<Func<T, TProperty>> expression, string expressionParameterName)
			{
				Guard.IsIndexerGetter(expression, expressionParameterName);
				return expression.Body as MethodCallExpression;
			}

			public void Setup<TProperty>(Expression<Func<TAnalog, TProperty>> expression, TProperty initialValue, string expressionParameterName, Func<LambdaExpression,LambdaExpression> duckReplacer)
			{
				var duckExpression = (Expression<Func<T,TProperty>>)duckReplacer(expression);
				var methodCall = GetGetter(duckExpression, expressionParameterName);
				var arguments = methodCall.Arguments.Select(a => a.PartialEval());
				Guard.AreConstantExpressions(arguments, nameof(expressionParameterName));

				List<IndexerArgsToValue<TProperty>> IndexerArgsToValues = new List<IndexerArgsToValue<TProperty>>();
				IndexerArgsToValues.Add(
					new IndexerArgsToValue<TProperty>(
						arguments.Cast<ConstantExpression>().Select(exp => exp.Value).ToList(),
						initialValue
					)
				);
				TProperty getterValue = default(TProperty);

				var method = methodCall.Method;
				var setterMethod = GetSetter(method);
				var setterItIsAny = GetSetterItIsAny(setterMethod);

				var parameter = Expression.Parameter(typeof(T));
				Expression[] gettertItAnyArguments = setterItIsAny.Take(setterItIsAny.Length - 1).ToArray();

				var getterSetup = SetUp(method, gettertItAnyArguments);
				getterSetup.SetCallbackBehavior(new Action<IInvocation>(invocation =>
				{
					var arguments = invocation.Arguments;
					getterValue = default(TProperty);
					foreach (var indexerArgsToValue in IndexerArgsToValues)
					{
						var match = indexerArgsToValue.HasArgs(arguments.ToList());
						if (match)
						{
							getterValue = indexerArgsToValue.value;
							break;
						}
					}
				}));
				getterSetup.SetReturnComputedValueBehavior(new Func<IInvocation, TProperty>((_) => getterValue));

				SetUp(setterMethod, setterItIsAny, duckReplacer).SetCallbackBehavior(new Action<IInvocation>(invocation =>
				{
					var arguments = invocation.Arguments;
					var keys = arguments.Take(arguments.Count - 1).ToList();
					var value = arguments.Last();
					IndexerArgsToValue<TProperty> matching = default;
					var matched = false;
					foreach (var indexerArgsToValue in IndexerArgsToValues)
					{
						if (indexerArgsToValue.HasArgs(keys))
						{
							matching = indexerArgsToValue;
							matched = true;
							break;
						}
					}
					if (matched)
					{
						IndexerArgsToValues.Remove(matching);

					}

					IndexerArgsToValues.Add(new IndexerArgsToValue<TProperty>(keys, (TProperty)value));
				}));

			}

			private MethodCall SetUp(MethodInfo method, Expression[] itIsAnyExpressions, Func<LambdaExpression, LambdaExpression> duckReplacer = null)
			{
				Type parameterType = typeof(T);
				if (duckReplacer != null)
				{
					parameterType = typeof(TAnalog);
				}
				var parameter = Expression.Parameter(parameterType);
				var methodCallExpression = Expression.Call(parameter, method, itIsAnyExpressions);
				var lambda = Expression.Lambda(methodCallExpression, parameter);
				if (duckReplacer != null)
				{
					lambda = duckReplacer(lambda);
				}
				return Mock.Setup(mock, lambda, null);
			}

			private MethodInfo GetSetter(MethodInfo getter)
			{
				var methodName = getter.Name;
				var types = getter.GetParameters().Select(p => p.ParameterType).Concat(new Type[] { getter.ReturnType }).ToArray();
				return typeof(TAnalog).GetMethod(
					$"s{methodName.Substring(1)}",
					BindingFlags.Public | BindingFlags.Instance,
					null,
					types,
					null
				);
			}

			private Expression[] GetSetterItIsAny(MethodInfo setterMethod)
			{
				var parameters = setterMethod.GetParameters();
				return parameters.Select(p =>
				{
					var pType = p.ParameterType;
					var itIsAny = itIsAnyMethod.MakeGenericMethod(pType);
					return Expression.Call(itIsAny);

				}).ToArray();


			}

			private struct IndexerArgsToValue<TProperty>
			{
				public List<object> args;
				public TProperty value;

				public IndexerArgsToValue(List<object> args, TProperty value)
				{
					this.args = args;
					this.value = value;
				}

				public bool HasArgs(IList<object> otherArgs)
				{
					if (args.Count != otherArgs.Count)
					{
						return false;
					}

					for (var i = 0; i < args.Count; i++)
					{
						if (!object.Equals(args[i], otherArgs[i]))
						{
							return false;
						}
					}
					return true;
				}

			}

		}
	}
}
